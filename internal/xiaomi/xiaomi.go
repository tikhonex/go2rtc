package xiaomi

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/AlexxIT/go2rtc/internal/api"
	"github.com/AlexxIT/go2rtc/internal/app"
	"github.com/AlexxIT/go2rtc/internal/streams"
	"github.com/AlexxIT/go2rtc/pkg/core"
	"github.com/AlexxIT/go2rtc/pkg/xiaomi"
	"github.com/AlexxIT/go2rtc/pkg/xiaomi/crypto"
	"github.com/AlexxIT/go2rtc/pkg/xiaomi/miss/cs2"
	"github.com/rs/zerolog"
)

func Init() {
	var v struct {
		Cfg map[string]string `yaml:"xiaomi"`
	}
	app.LoadConfig(&v)

	tokens = v.Cfg

	log = app.GetLogger("xiaomi")

	streams.HandleFunc("xiaomi", func(rawURL string) (core.Producer, error) {
		u, err := url.Parse(rawURL)
		if err != nil {
			return nil, err
		}

		if u.User != nil {
			rawURL, err = getCameraURL(u)
			if err != nil {
				return nil, err
			}
		}

		log.Debug().Msgf("xiaomi: dial %s", rawURL)

		return xiaomi.Dial(rawURL)
	})

	api.HandleFunc("api/xiaomi", apiXiaomi)
}

var log zerolog.Logger

var tokens map[string]string
var clouds map[string]*xiaomi.Cloud
var cloudsMu sync.Mutex

// The cloud session (serviceToken) expires after several days. On 401 the
// cached session is dropped and a new one is made from the passToken in the
// config. A failed login is not retried earlier than cloudRetryDelay, and if
// new sessions keep getting 401, the pause between resets doubles up to
// cloudMaxDelay. So a rejected token can't turn every stream reconnect into
// a login request to account.xiaomi.com.
var cloudRetryDelay = time.Minute
var cloudMaxDelay = 30 * time.Minute
var cloudResets = map[string]cloudReset{}
var loginErrors = map[string]loginError{}

type cloudReset struct {
	time  time.Time
	delay time.Duration // no new reset before time + delay
}

type loginError struct {
	err  error
	time time.Time
}

func getCloud(userID string) (*xiaomi.Cloud, error) {
	cloudsMu.Lock()
	defer cloudsMu.Unlock()

	if cloud := clouds[userID]; cloud != nil {
		return cloud, nil
	}

	if e, ok := loginErrors[userID]; ok && time.Since(e.time) < cloudRetryDelay {
		return nil, e.err
	}

	cloud := xiaomi.NewCloud(AppXiaomiHome)
	if err := cloud.LoginWithToken(userID, tokens[userID]); err != nil {
		loginErrors[userID] = loginError{err: err, time: time.Now()}
		return nil, err
	}
	delete(loginErrors, userID)

	if clouds == nil {
		clouds = map[string]*xiaomi.Cloud{userID: cloud}
	} else {
		clouds[userID] = cloud
	}
	return cloud, nil
}

// resetCloud drops the cached session if it is still the one that got 401.
// Returns false if it is too early for another reset.
func resetCloud(userID string, cloud *xiaomi.Cloud) bool {
	cloudsMu.Lock()
	defer cloudsMu.Unlock()

	if clouds[userID] != cloud {
		return true // already replaced by another request
	}

	r := cloudResets[userID]
	since := time.Since(r.time)
	if since < r.delay {
		return false
	}
	if since < 2*cloudMaxDelay {
		// the previous new session was rejected soon after login
		r.delay = min(r.delay*2, cloudMaxDelay)
	} else {
		r.delay = cloudRetryDelay
	}
	r.time = time.Now()
	cloudResets[userID] = r

	delete(clouds, userID)

	log.Warn().Msgf("xiaomi: cloud session expired, login again user=%s next_reset_after=%s", userID, r.delay)
	return true
}

func cloudRequest(userID, region, apiURL, params string) ([]byte, error) {
	cloud, err := getCloud(userID)
	if err != nil {
		return nil, err
	}

	res, err := cloud.Request(GetBaseURL(region), apiURL, params, nil)
	if !errors.Is(err, xiaomi.ErrUnauthorized) || !resetCloud(userID, cloud) {
		return res, err
	}

	if cloud, err = getCloud(userID); err != nil {
		return nil, err
	}
	return cloud.Request(GetBaseURL(region), apiURL, params, nil)
}

func cloudUserRequest(user *url.Userinfo, apiURL, params string) ([]byte, error) {
	userID := user.Username()
	region, _ := user.Password()
	return cloudRequest(userID, region, apiURL, params)
}

func getCameraURL(url *url.URL) (string, error) {
	model := url.Query().Get("model")

	// It is not known which models need to be awakened.
	// Probably all the doorbells and all the battery cameras.
	if strings.Contains(model, ".cateye.") {
		_ = wakeUpCamera(url)
	}

	// The getMissURL request has a fallback to getP2PURL.
	// But for known models we can save one request to the cloud.
	if xiaomi.IsLegacy(model) {
		return getLegacyURL(url)
	}
	return getMissURL(url)
}

func getLegacyURL(url *url.URL) (string, error) {
	query := url.Query()

	clientPublic, clientPrivate, err := crypto.GenerateKey()
	if err != nil {
		return "", err
	}

	params := fmt.Sprintf(`{"did":"%s","toSignAppData":"%x"}`, query.Get("did"), clientPublic)

	userID := url.User.Username()
	region, _ := url.User.Password()
	res, err := cloudRequest(userID, region, "/device/devicepass", params)
	if err != nil {
		return "", err
	}

	var v struct {
		UID       string `json:"p2p_id"`
		Password  string `json:"password"`
		PublicKey string `json:"p2p_dev_public_key"`
		Sign      string `json:"signForAppData"`
	}
	if err = json.Unmarshal(res, &v); err != nil {
		return "", err
	}

	query.Set("uid", v.UID)

	if v.Sign != "" {
		query.Set("client_public", hex.EncodeToString(clientPublic))
		query.Set("client_private", hex.EncodeToString(clientPrivate))
		query.Set("device_public", v.PublicKey)
		query.Set("sign", v.Sign)
	} else {
		query.Set("password", v.Password)
	}

	url.RawQuery = query.Encode()
	return url.String(), nil
}

// cloudEnabledForDID сообщает, разрешён ли облачный путь CS2 для данного did.
// Список did задаётся через GO2RTC_CS2_CLOUD_DIDS (через запятую). Пусто —
// облачный путь выключен для всех, и каждая камера работает как раньше.
func cloudEnabledForDID(did string) bool {
	list := os.Getenv("GO2RTC_CS2_CLOUD_DIDS")
	if list == "" || did == "" {
		return false
	}
	for _, d := range strings.Split(list, ",") {
		if strings.TrimSpace(d) == did {
			return true
		}
	}
	return false
}

func getMissURL(url *url.URL) (string, error) {
	clientPublic, clientPrivate, err := crypto.GenerateKey()
	if err != nil {
		return "", err
	}

	query := url.Query()
	params := fmt.Sprintf(
		`{"app_pubkey":"%x","did":"%s","support_vendors":"TUTK_CS2_MTP"}`,
		clientPublic, query.Get("did"),
	)

	res, err := cloudUserRequest(url.User, "/v2/device/miss_get_vendor", params)
	if err != nil {
		if strings.Contains(err.Error(), "no available vendor support") {
			return getLegacyURL(url)
		}
		return "", err
	}

	var v struct {
		Vendor struct {
			ID     byte `json:"vendor"`
			Params struct {
				UID        string `json:"p2p_id"`
				InitString string `json:"init_string"`
			} `json:"vendor_params"`
		} `json:"vendor"`
		PublicKey string `json:"public_key"`
		Sign      string `json:"sign"`
	}
	if err = json.Unmarshal(res, &v); err != nil {
		return "", err
	}

	query.Set("client_public", hex.EncodeToString(clientPublic))
	query.Set("client_private", hex.EncodeToString(clientPrivate))
	query.Set("device_public", v.PublicKey)
	query.Set("sign", v.Sign)
	query.Set("vendor", getVendorName(v.Vendor.ID))

	if v.Vendor.ID == 1 {
		query.Set("uid", v.Vendor.Params.UID)
	}

	// Облачный путь CS2 — ТОЛЬКО для камер, чей did перечислен в
	// GO2RTC_CS2_CLOUD_DIDS (через запятую). Это камеры в другом доме,
	// до которых нет локальной сети. Все прочие камеры сюда не заходят
	// и работают ровно как раньше — прямым локальным cs2.Dial.
	//
	// Серверы берутся из init_string того же ответа облака (по три штуки
	// на камеру, привязаны к региону), а НЕ из зашитого адреса: зашитый
	// 47.236.156.107 отвечает этим did кодом INVALID_PREFIX. url.Host не
	// трогаем — там LAN-адрес камеры, он ещё нужен как подсказка.
	if v.Vendor.Params.UID != "" && cloudEnabledForDID(query.Get("did")) {
		servers := cs2.DecodeInitString(v.Vendor.Params.InitString)
		if env := os.Getenv("GO2RTC_CS2_RELAY"); env != "" {
			servers = strings.Split(env, ",") // ручное переопределение для отладки
		}
		if len(servers) == 0 {
			return "", fmt.Errorf("xiaomi: cs2 cloud: не удалось расшифровать init_string для did %s",
				query.Get("did"))
		}
		query.Set("p2p_id", v.Vendor.Params.UID)
		query.Set("p2p_servers", strings.Join(servers, ","))
		log.Debug().Msgf("xiaomi: cs2 cloud did=%s servers=%v", query.Get("did"), servers)
	}

	url.RawQuery = query.Encode()
	return url.String(), nil
}

func getVendorName(i byte) string {
	switch i {
	case 1:
		return "tutk"
	case 3:
		return "agora"
	case 4:
		return "cs2"
	case 6:
		return "mtp"
	}
	return fmt.Sprintf("%d", i)
}

func wakeUpCamera(url *url.URL) error {
	const params = `{"id":1,"method":"wakeup","params":{"video":"1"}}`
	did := url.Query().Get("did")
	_, err := cloudUserRequest(url.User, "/home/rpc/"+did, params)
	return err
}

func apiXiaomi(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		apiDeviceList(w, r)
	case "POST":
		apiAuth(w, r)
	}
}

func apiDeviceList(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()

	user := query.Get("id")
	if user == "" {
		cloudsMu.Lock()
		users := make([]string, 0, len(tokens))
		for s := range tokens {
			users = append(users, s)
		}
		cloudsMu.Unlock()

		api.ResponseJSON(w, users)
		return
	}

	err := func() error {
		region := query.Get("region")
		res, err := cloudRequest(user, region, "/v2/home/device_list_page", "{}")
		if err != nil {
			return err
		}
		var v struct {
			List []*Device `json:"list"`
		}

		log.Trace().Str("user", user).Msgf("[xiaomi] devices list: %s", res)

		if err = json.Unmarshal(res, &v); err != nil {
			return err
		}

		var items []*api.Source

		for _, device := range v.List {
			if !device.HasCamera() {
				continue
			}
			items = append(items, &api.Source{
				Name: device.Name,
				Info: fmt.Sprintf("ip: %s, mac: %s", device.IP, device.MAC),
				URL:  fmt.Sprintf("xiaomi://%s:%s@%s?did=%s&model=%s", user, region, device.IP, device.Did, device.Model),
			})
		}

		api.ResponseSources(w, items)
		return nil
	}()

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

type Device struct {
	Did   string `json:"did"`
	Name  string `json:"name"`
	Model string `json:"model"`
	MAC   string `json:"mac"`
	IP    string `json:"localip"`
}

func (d *Device) HasCamera() bool {
	return strings.Contains(d.Model, ".camera.") ||
		strings.Contains(d.Model, ".cateye.") ||
		strings.Contains(d.Model, ".feeder.")
}

var auth *xiaomi.Cloud

func apiAuth(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	username := r.Form.Get("username")
	password := r.Form.Get("password")
	captcha := r.Form.Get("captcha")
	verify := r.Form.Get("verify")

	var err error

	switch {
	case username != "" || password != "":
		auth = xiaomi.NewCloud(AppXiaomiHome)
		err = auth.Login(username, password)
	case captcha != "":
		err = auth.LoginWithCaptcha(captcha)
	case verify != "":
		err = auth.LoginWithVerify(verify)
	default:
		http.Error(w, "wrong request", http.StatusBadRequest)
		return
	}

	if err == nil {
		userID, token := auth.UserToken()
		auth = nil

		cloudsMu.Lock()
		if tokens == nil {
			tokens = map[string]string{userID: token}
		} else {
			tokens[userID] = token
		}
		delete(loginErrors, userID) // try the new token right away
		cloudsMu.Unlock()

		err = app.PatchConfig([]string{"xiaomi", userID}, token)
	}

	if err != nil {
		var login *xiaomi.LoginError
		if errors.As(err, &login) {
			w.Header().Set("Content-Type", api.MimeJSON)
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(err)
			return
		}

		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

const AppXiaomiHome = "xiaomiio"

func GetBaseURL(region string) string {
	switch region {
	case "de", "i2", "ru", "sg", "us":
		return "https://" + region + ".api.io.mi.com/app"
	}
	return "https://api.io.mi.com/app"
}
