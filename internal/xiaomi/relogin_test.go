package xiaomi

import (
	"crypto/rc4"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AlexxIT/go2rtc/pkg/xiaomi"
	"github.com/stretchr/testify/require"
)

var testSsecurity = []byte("0123456789abcdef")

// fakeCloud imitates account.xiaomi.com (login) and api.io.mi.com (requests).
// Every successful login issues serviceToken "tokenN"; the API accepts only
// the token in valid and answers 401 to any other.
type fakeCloud struct {
	mu        sync.Mutex
	attempts  int // serviceLogin calls, including failed
	logins    int // successful serviceLogin calls
	loginFail bool
	valid     string
	requests  []string // serviceToken of every API request
}

func (f *fakeCloud) RoundTrip(req *http.Request) (*http.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	switch req.URL.Host {
	case "account.xiaomi.com":
		f.attempts++
		if f.loginFail {
			return nil, errors.New("fake login timeout")
		}
		f.logins++
		body := `&&&START&&&{"ssecurity":"` + base64.StdEncoding.EncodeToString(testSsecurity) +
			`","passToken":"pass","location":"https://sts.fake/sts?n=` + strconv.Itoa(f.logins) + `"}`
		return fakeResponse(req, http.StatusOK, body, nil), nil

	case "sts.fake":
		header := http.Header{}
		header.Add("Set-Cookie", "userId=123")
		header.Add("Set-Cookie", "cUserId=c123")
		header.Add("Set-Cookie", "serviceToken=token"+req.URL.Query().Get("n"))
		return fakeResponse(req, http.StatusOK, "", header), nil

	case "api.io.mi.com":
		token := ""
		if c, err := req.Cookie("serviceToken"); err == nil {
			token = c.Value
		}
		f.requests = append(f.requests, token)
		if token != f.valid {
			return fakeResponse(req, http.StatusUnauthorized, "", nil), nil
		}

		_ = req.ParseForm()
		nonce, _ := base64.StdEncoding.DecodeString(req.PostForm.Get("_nonce"))
		hasher := sha256.New()
		hasher.Write(testSsecurity)
		hasher.Write(nonce)
		cipher, _ := rc4.NewCipher(hasher.Sum(nil))
		tmp := make([]byte, 1024)
		cipher.XORKeyStream(tmp, tmp)
		plaintext := []byte(`{"code":0,"result":"ok-` + token + `"}`)
		ciphertext := make([]byte, len(plaintext))
		cipher.XORKeyStream(ciphertext, plaintext)
		return fakeResponse(req, http.StatusOK, base64.StdEncoding.EncodeToString(ciphertext), nil), nil
	}

	return nil, errors.New("unexpected host " + req.URL.Host)
}

func (f *fakeCloud) stats() (attempts, logins int, requests []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.attempts, f.logins, append([]string(nil), f.requests...)
}

func (f *fakeCloud) set(fn func(f *fakeCloud)) {
	f.mu.Lock()
	fn(f)
	f.mu.Unlock()
}

func fakeResponse(req *http.Request, code int, body string, header http.Header) *http.Response {
	if header == nil {
		header = http.Header{}
	}
	return &http.Response{
		StatusCode: code,
		Status:     strconv.Itoa(code) + " " + http.StatusText(code),
		Header:     header,
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
	}
}

func setupFakeCloud(t *testing.T) *fakeCloud {
	f := &fakeCloud{valid: "token1"}

	transport := http.DefaultTransport
	retryDelay, maxDelay := cloudRetryDelay, cloudMaxDelay
	http.DefaultTransport = f
	t.Cleanup(func() {
		http.DefaultTransport = transport
		cloudRetryDelay, cloudMaxDelay = retryDelay, maxDelay
	})

	tokens = map[string]string{"123": "pass"}
	clouds = nil
	cloudResets = map[string]cloudReset{}
	loginErrors = map[string]loginError{}
	return f
}

func TestCloudReloginOn401(t *testing.T) {
	f := setupFakeCloud(t)

	res, err := cloudRequest("123", "cn", "/v2/device/miss_get_vendor", "{}")
	require.NoError(t, err)
	require.Equal(t, `"ok-token1"`, string(res))

	// serviceToken expired: the cloud stops accepting token1
	f.set(func(f *fakeCloud) { f.valid = "token2" })

	res, err = cloudRequest("123", "cn", "/v2/device/miss_get_vendor", "{}")
	require.NoError(t, err)
	require.Equal(t, `"ok-token2"`, string(res))

	_, logins, requests := f.stats()
	require.Equal(t, 2, logins)
	require.Equal(t, []string{"token1", "token1", "token2"}, requests)
}

func TestCloudReloginRateLimit(t *testing.T) {
	f := setupFakeCloud(t)
	f.set(func(f *fakeCloud) { f.valid = "token2" })

	// first 401 -> relogin -> success
	_, err := cloudRequest("123", "cn", "/api", "{}")
	require.NoError(t, err)

	// cloud rejects the new session right away: no second login within delay
	f.set(func(f *fakeCloud) { f.valid = "token3" })
	_, err = cloudRequest("123", "cn", "/api", "{}")
	require.ErrorIs(t, err, xiaomi.ErrUnauthorized)
	require.Equal(t, "401 Unauthorized", err.Error()) // watchdog greps this text

	_, logins, _ := f.stats()
	require.Equal(t, 2, logins)

	// after the delay the next 401 logs in again
	cloudResets["123"] = cloudReset{time: time.Now().Add(-2 * time.Minute), delay: time.Minute}
	res, err := cloudRequest("123", "cn", "/api", "{}")
	require.NoError(t, err)
	require.Equal(t, `"ok-token3"`, string(res))

	_, logins, _ = f.stats()
	require.Equal(t, 3, logins)
}

func TestCloudReloginBackoff(t *testing.T) {
	f := setupFakeCloud(t)
	cloudRetryDelay = 40 * time.Millisecond
	cloudMaxDelay = 160 * time.Millisecond

	_, err := cloudRequest("123", "cn", "/api", "{}")
	require.NoError(t, err)

	// every new session is rejected too (not an expiry)
	f.set(func(f *fakeCloud) { f.valid = "never" })

	request := func() {
		_, err := cloudRequest("123", "cn", "/api", "{}")
		require.ErrorIs(t, err, xiaomi.ErrUnauthorized)
	}
	logins := func() int {
		_, n, _ := f.stats()
		return n
	}

	request() // reset 1, delay 40ms
	require.Equal(t, 2, logins())
	require.Equal(t, 40*time.Millisecond, cloudResets["123"].delay)

	request() // too early
	require.Equal(t, 2, logins())

	time.Sleep(50 * time.Millisecond)
	request() // reset 2, delay doubles to 80ms
	require.Equal(t, 3, logins())
	require.Equal(t, 80*time.Millisecond, cloudResets["123"].delay)

	time.Sleep(50 * time.Millisecond)
	request() // 50ms < 80ms
	require.Equal(t, 3, logins())

	time.Sleep(40 * time.Millisecond)
	request() // reset 3, delay 160ms (max)
	require.Equal(t, 4, logins())
	require.Equal(t, 160*time.Millisecond, cloudResets["123"].delay)

	time.Sleep(170 * time.Millisecond)
	request() // reset 4, delay stays at max
	require.Equal(t, 5, logins())
	require.Equal(t, 160*time.Millisecond, cloudResets["123"].delay)

	// a long time without resets: the next expiry starts from the short delay
	cloudResets["123"] = cloudReset{time: time.Now().Add(-time.Hour), delay: cloudMaxDelay}
	f.set(func(f *fakeCloud) { f.valid = "token6" })
	_, err = cloudRequest("123", "cn", "/api", "{}")
	require.NoError(t, err)
	require.Equal(t, 6, logins())
	require.Equal(t, cloudRetryDelay, cloudResets["123"].delay)
}

func TestCloudPersistent401LoginRate(t *testing.T) {
	f := setupFakeCloud(t)
	cloudRetryDelay = 10 * time.Millisecond
	cloudMaxDelay = 10 * time.Second

	_, err := cloudRequest("123", "cn", "/api", "{}")
	require.NoError(t, err)
	f.set(func(f *fakeCloud) { f.valid = "never" })

	// 8 streams hammer the cloud for 500ms: without backoff it would be
	// ~50 logins (one per 10ms), with doubling it is about log2(500/10)
	var wg sync.WaitGroup
	stop := time.Now().Add(500 * time.Millisecond)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(stop) {
				_, _ = cloudRequest("123", "cn", "/api", "{}")
				time.Sleep(time.Millisecond)
			}
		}()
	}
	wg.Wait()

	attempts, _, _ := f.stats()
	require.LessOrEqual(t, attempts, 1+8)
	require.GreaterOrEqual(t, attempts, 1+4)
}

func TestCloudLoginErrorCached(t *testing.T) {
	f := setupFakeCloud(t)
	f.set(func(f *fakeCloud) { f.loginFail = true })

	for i := 0; i < 5; i++ {
		_, err := cloudRequest("123", "cn", "/api", "{}")
		require.ErrorContains(t, err, "fake login timeout")
	}

	attempts, _, requests := f.stats()
	require.Equal(t, 1, attempts) // the other 4 got the cached error
	require.Empty(t, requests)

	f.set(func(f *fakeCloud) { f.loginFail = false })
	cloudRetryDelay = 10 * time.Millisecond
	time.Sleep(20 * time.Millisecond)

	res, err := cloudRequest("123", "cn", "/api", "{}")
	require.NoError(t, err)
	require.Equal(t, `"ok-token1"`, string(res))
}

func TestCloudReloginConcurrent(t *testing.T) {
	f := setupFakeCloud(t)

	_, err := cloudRequest("123", "cn", "/api", "{}")
	require.NoError(t, err)

	f.set(func(f *fakeCloud) { f.valid = "token2" })

	var wg sync.WaitGroup
	errs := make([]error, 20)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = cloudRequest("123", "cn", "/api", "{}")
		}(i)
	}
	wg.Wait()

	for _, err := range errs {
		require.NoError(t, err)
	}

	_, logins, _ := f.stats()
	require.Equal(t, 2, logins) // all 20 requests shared one relogin
}
