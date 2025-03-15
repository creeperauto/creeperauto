package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/smtp"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/PuerkitoBio/goquery"
	"github.com/joho/godotenv"
)

// Notifier 接口定义通知行为
type Notifier interface {
	Send(message string) error
}

// MailNotifier 邮件通知实现
type MailNotifier struct {
	host     string
	port     int
	username string
	password string
	to       string
}

func (m *MailNotifier) Send(message string) error {
	auth := smtp.PlainAuth("", m.username, m.password, m.host)
	msg := []byte(fmt.Sprintf("To: %s\r\nSubject: CreeperAuto Sign-in Notification\r\n\r\n%s", m.to, message))
	addr := fmt.Sprintf("%s:%d", m.host, m.port)
	return smtp.SendMail(addr, auth, m.username, []string{m.to}, msg)
}

// WechatNotifier 企业微信通知实现
type WechatNotifier struct {
	webhook   string
	mentioned []string
}

func (w *WechatNotifier) Send(message string) error {
	data := map[string]interface{}{
		"msgtype": "text",
		"text": map[string]interface{}{
			"content": message,
		},
	}
	if len(w.mentioned) > 0 {
		data["text"].(map[string]interface{})["mentioned_list"] = w.mentioned
	}
	jsonData, _ := json.Marshal(data)
	_, err := http.Post(w.webhook, "application/json", bytes.NewBuffer(jsonData))
	return err
}

// ServerchanNotifier ServerChan 通知实现
type ServerchanNotifier struct {
	key string
}

func (s *ServerchanNotifier) Send(message string) error {
	targetURL := fmt.Sprintf("https://sctapi.ftqq.com/%s.send", s.key)
	data := url.Values{
		"title": []string{"CreeperAuto Sign-in"},
		"desp":  []string{message},
	}
	_, err := http.PostForm(targetURL, data)
	return err
}

// NtfyNotifier Ntfy 通知实现
type NtfyNotifier struct {
	url      string
	topic    string
	username string
	password string
	token    string
	client   *http.Client
}

func (n *NtfyNotifier) Send(message string) error {
	url := fmt.Sprintf("%s/%s", n.url, n.topic)
	req, err := http.NewRequest("POST", url, strings.NewReader(message))
	if err != nil {
		return err
	}
	if n.token != "" {
		req.Header.Set("Authorization", "Bearer "+n.token)
	} else if n.username != "" && n.password != "" {
		req.SetBasicAuth(n.username, n.password)
	}
	_, err = n.client.Do(req)
	return err
}

// AutoSigner 自动签到工具结构体
type AutoSigner struct {
	username    string
	password    string
	switchUser  bool
	renewalVIP  bool
	renewalSVIP bool
	debug       bool
	notifiers   []Notifier
	client      *http.Client
	headers     http.Header
}

// NewAutoSigner 初始化 AutoSigner
func NewAutoSigner(username, password string, notifiers []Notifier) *AutoSigner {
	client := &http.Client{}
	headers := make(http.Header)
	headers.Set("Content-Type", "application/x-www-form-urlencoded")

	return &AutoSigner{
		username:    username,
		password:    password,
		switchUser:  envBool("SWITCH_USER"),
		renewalVIP:  envBool("RENEWAL_VIP"),
		renewalSVIP: envBool("RENEWAL_SVIP"),
		debug:       envBool("DEBUG"),
		notifiers:   notifiers,
		client:      client,
		headers:     headers,
	}
}

// envBool 获取布尔型环境变量
func envBool(key string) bool {
	val, _ := strconv.ParseBool(os.Getenv(key))
	return val
}

// envInt 获取整型环境变量
func envInt(key string) int {
	val, _ := strconv.Atoi(os.Getenv(key))
	return val
}

// setupLogging 设置日志格式
func (c *AutoSigner) setupLogging() {
	if c.debug {
		log.SetFlags(log.LstdFlags | log.Lshortfile)
	} else {
		log.SetFlags(log.LstdFlags)
	}
}

// login 执行登录
func (c *AutoSigner) login() error {
	postURL := "https://klpbbs.com/member.php?mod=logging&action=login&loginsubmit=yes"
	data := url.Values{
		"username": {c.username},
		"password": {c.password},
	}
	req, err := http.NewRequest("POST", postURL, strings.NewReader(data.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create login request: %v", err)
	}
	req.Header = c.headers
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("login failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("login failed with status: %v", resp.Status)
	}
	log.Println("Login successful for user:", c.username)
	return nil
}

// getSignInURL 获取签到链接
func (c *AutoSigner) getSignInURL() (string, error) {
	resp, err := c.client.Get("https://klpbbs.com/")
	if err != nil {
		return "", fmt.Errorf("failed to get homepage: %v", err)
	}
	defer resp.Body.Close()
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to parse HTML: %v", err)
	}
	signInURL := ""
	doc.Find("a.midaben_signpanel.JD_sign").Each(func(i int, s *goquery.Selection) {
		if href, exists := s.Attr("href"); exists {
			signInURL = "https://klpbbs.com/" + href
		}
	})
	return signInURL, nil
}

// performSignIn 执行签到
func (c *AutoSigner) performSignIn(signInURL string) error {
	resp, err := c.client.Get(signInURL)
	if err != nil {
		return fmt.Errorf("sign-in failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("sign-in failed with status: %v", resp.Status)
	}
	log.Println("Sign-in successful for user:", c.username)
	return nil
}

// isSignedIn 检查签到状态
func (c *AutoSigner) isSignedIn() (bool, error) {
	resp, err := c.client.Get("https://klpbbs.com/")
	if err != nil {
		return false, fmt.Errorf("failed to check sign-in status: %v", err)
	}
	defer resp.Body.Close()
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return false, fmt.Errorf("failed to parse HTML: %v", err)
	}
	signed := doc.Find("a.midaben_signpanel.JD_sign").Length() == 0
	if signed {
		log.Println("Sign-in status: Already signed in for user:", c.username)
		return true, nil
	}
	log.Println("Sign-in status: Not signed in for user:", c.username)
	return false, nil
}

// notify 发送通知
func (c *AutoSigner) notify(message string) {
	var wg sync.WaitGroup
	for _, notifier := range c.notifiers {
		wg.Add(1)
		go func(n Notifier) {
			defer wg.Done()
			if err := n.Send(message); err != nil {
				log.Printf("Failed to send notification: %v", err)
			}
		}(notifier)
	}
	wg.Wait()
}

// signInWorker 签到工作函数
func signInWorker(username, password string, notifiers []Notifier, wg *sync.WaitGroup) {
	defer wg.Done()
	autoSigner := NewAutoSigner(username, password, notifiers)
	autoSigner.setupLogging()

	log.Println("Starting login for user:", username)
	if err := autoSigner.login(); err != nil {
		log.Printf("Login error for user %s: %v", username, err)
		autoSigner.notify(fmt.Sprintf("【%s】登录失败: %v", username, err))
		return
	}

	log.Println("Fetching sign-in URL for user:", username)
	signInURL, err := autoSigner.getSignInURL()
	if err != nil {
		log.Printf("Error fetching sign-in URL for user %s: %v", username, err)
		autoSigner.notify(fmt.Sprintf("【%s】获取签到链接失败: %v", username, err))
		return
	}

	if signInURL != "" {
		log.Println("Signing in for user:", username)
		if err := autoSigner.performSignIn(signInURL); err != nil {
			log.Printf("Sign-in error for user %s: %v", username, err)
			autoSigner.notify(fmt.Sprintf("【%s】签到失败: %v", username, err))
			return
		}
	} else {
		log.Println("Sign-in URL not found for user:", username, "may already be signed in")
	}

	log.Println("Checking sign-in status for user:", username)
	signed, err := autoSigner.isSignedIn()
	if err != nil {
		log.Printf("Error checking sign-in status for user %s: %v", username, err)
		autoSigner.notify(fmt.Sprintf("【%s】检查签到状态失败: %v", username, err))
		return
	}

	if signed {
		autoSigner.notify(fmt.Sprintf("【%s】签到成功", username))
	} else {
		autoSigner.notify(fmt.Sprintf("【%s】签到失败", username))
	}
}

// main 主函数
func main() {
	version := "0.0.1"
	log.Println("CreeperAuto Version:", version)

	// 加载.env文件
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	// 初始化通知器
	var notifiers []Notifier
	if envBool("MAIL_ENABLE") {
		notifiers = append(notifiers, &MailNotifier{
			host:     os.Getenv("MAIL_HOST"),
			port:     envInt("MAIL_PORT"),
			username: os.Getenv("MAIL_USERNAME"),
			password: os.Getenv("MAIL_PASSWORD"),
			to:       os.Getenv("MAIL_TO"),
		})
	}
	if envBool("WECHAT_ENABLE") {
		notifiers = append(notifiers, &WechatNotifier{
			webhook:   os.Getenv("WECHAT_WEBHOOK"),
			mentioned: strings.Split(os.Getenv("WECHAT_MENTIONED"), ","),
		})
	}
	if envBool("SERVERCHAN_ENABLE") {
		notifiers = append(notifiers, &ServerchanNotifier{
			key: os.Getenv("SERVERCHAN_KEY"),
		})
	}
	if envBool("NTFY_ENABLE") {
		notifiers = append(notifiers, &NtfyNotifier{
			url:      os.Getenv("NTFY_URL"),
			topic:    os.Getenv("NTFY_TOPIC"),
			username: os.Getenv("NTFY_USERNAME"),
			password: os.Getenv("NTFY_PASSWORD"),
			token:    os.Getenv("NTFY_TOKEN"),
			client:   &http.Client{},
		})
	}

	// 获取多用户凭据
	userCredentials := os.Getenv("USER_CREDENTIALS")
	if userCredentials == "" {
		log.Fatal("USER_CREDENTIALS environment variable is not set")
	}
	users := strings.Split(userCredentials, ",")
	var wg sync.WaitGroup
	for _, user := range users {
		parts := strings.Split(user, ":")
		if len(parts) != 2 {
			log.Printf("Invalid user credential format: %s", user)
			continue
		}
		username, password := parts[0], parts[1]
		wg.Add(1)
		go signInWorker(username, password, notifiers, &wg)
	}
	wg.Wait()
}
