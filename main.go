package main

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"time"
)

const (
	HOST           = "https://www.114yygh.com"
	Firstdeptcode  = "36a8b3fef7aaedcc2b0f544c81582dd7" // 科室
	Seconddeptcode = "200000240"                        // 陪住家属筛查门诊
	Hoscode        = "126"                              // 北医三院
	Target         = "2021-04-30"
	Phone          = "17600231222"
	CardType       = "SOCIAL_SECURITY" // 医保卡
	CardID         = "119712313003"
	Keywords       = "普通" // 根据keywords匹配医生名来挂号
)

var (
	client *http.Client
)

func init() {
	client = &http.Client{Timeout: 3 * time.Second}
	jar, err := cookiejar.New(nil)
	if err != nil {
		log.Fatalf("cookie new err:%v", err)
	}
	client.Jar = jar
}

func HttpSend(url, method string, body, response interface{}) error {
	log.Printf("HttpSend:%v %v %+v", url, method, body)
	// 超时时间：5秒
	var req *http.Request
	var err error
	if method == "POST" {
		bodyByts, err := json.Marshal(body)
		if err != nil {
			return err
		}
		req, err = http.NewRequest(http.MethodPost, url, bytes.NewReader(bodyByts))
		if err != nil {
			return err
		}
	} else {
		req, err = http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			return err
		}
	}
	req.Header.Add("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Safari/537.36")
	req.Header.Add("Referer", "https://www.114yygh.com/")
	req.Header.Add("Request-Source", "PC")
	req.Header.Add("Origin", "https://www.114yygh.com")
	req.Header.Add("Host", "www.114yygh.com")
	req.Header.Add("Content-Type", "application/json;charset=UTF-8")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	respByts, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	log.Printf("HttpSend:resp=%v", string(respByts))
	if response == nil {
		return nil
	}
	if err := json.Unmarshal(respByts, response); err != nil {
		return err
	}
	return nil
}

func PKCS7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func AesEncrypt(origData, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	origData = PKCS7Padding(origData, blockSize)
	// blockMode := cipher.NewCBCEncrypter(block, key[:blockSize])
	crypted := make([]byte, len(origData))
	// blockMode.CryptBlocks(crypted, origData)
	block.Encrypt(crypted, origData)
	return crypted, nil
}

func code2Secret(code string) string {
	k := []byte("hyde2019hyde2019")

	secret, err := AesEncrypt([]byte(code), k)
	if err != nil {
		log.Fatalf("code2Secret err:%v", err)
	}

	secret1 := base64.StdEncoding.EncodeToString(secret)
	secret2 := strings.ReplaceAll(secret1, "+", "-")
	secret3 := strings.ReplaceAll(secret2, "/", "_")
	return secret3
}

func sendCode(phone string) error {
	url := fmt.Sprintf("%v/web/common/verify-code/get?mobile=%v&smsKey=LOGIN", HOST, phone)
	if err := HttpSend(url, "GET", nil, nil); err != nil {
		log.Printf("sendCode err:%v", err)
		return err
	}
	return nil
}

type VerifyCodeBody struct {
	Mobile string `json:"mobile"`
	Code   string `json:"code"`
}
type BaseResponse struct {
	Rescode int    `json:"resCode"`
	Msg     string `json:"msg"`
}

func (b BaseResponse) check() error {
	if b.Rescode != 0 {
		return errors.New(b.Msg)
	}
	return nil
}

func verifyCode(phone, code string) error {
	url := fmt.Sprintf("%v/web/login", HOST)
	body := &VerifyCodeBody{Mobile: code2Secret(phone), Code: code2Secret(code)}
	resp := &BaseResponse{}
	if err := HttpSend(url, "POST", body, resp); err != nil {
		log.Printf("verifyCode err:%v", err)
		return err
	}

	if resp.Rescode != 0 {
		log.Printf("verifyCode !=0, resp=%+v", resp)
		return errors.New(resp.Msg)
	}
	return nil
}

type DetailBody struct {
	Firstdeptcode  string `json:"firstDeptCode"`
	Seconddeptcode string `json:"secondDeptCode"`
	Hoscode        string `json:"hosCode"`
	Target         string `json:"target"`
}

type DetailResp struct {
	BaseResponse
	Data []DetailData `json:"data"`
}

type DetailData struct {
	Dutycode   string `json:"dutyCode"`
	Dutyimgurl string `json:"dutyImgUrl"`
	Detail     []struct {
		Uniqproductkey  string        `json:"uniqProductKey"`
		Doctorname      interface{}   `json:"doctorName"`
		Doctortitlename string        `json:"doctorTitleName"`
		Skill           string        `json:"skill"`
		Period          []interface{} `json:"period"`
		Ncode           string        `json:"ncode"`
		Wnumber         int           `json:"wnumber"`
		Fcode           string        `json:"fcode"`
		Znumber         int           `json:"znumber"`
	} `json:"detail"`
	Showindexposition int  `json:"showIndexPosition"`
	Shownumber        bool `json:"showNumber"`
	Showprice         bool `json:"showPrice"`
}

func detail(firstdeptcode, seconddeptcode, hoscode, target string) ([]DetailData, error) {
	url := fmt.Sprintf("%v/web/product/detail", HOST)
	body := &DetailBody{
		Firstdeptcode:  firstdeptcode,
		Seconddeptcode: seconddeptcode,
		Hoscode:        hoscode,
		Target:         target,
	}
	resp := &DetailResp{}
	if err := HttpSend(url, "POST", body, resp); err != nil {
		log.Printf("detail err:%v", err)
		return nil, err
	}
	return resp.Data, nil
}

func choise(details []DetailData) []string {
	uniqKeys := make([]string, 0)
	for _, halfDay := range details {
		log.Printf("----------%v----------", halfDay.Dutycode)
		log.Printf("部门 医生名 wnumber znumber key 是否选择")
		for _, item := range halfDay.Detail {
			selected := false
			if strings.Contains(item.Doctortitlename, Keywords) {
				uniqKeys = append(uniqKeys, item.Uniqproductkey)
				selected = true
			}
			log.Printf("%v %v %v %v %v %v", item.Doctortitlename, item.Doctorname, item.Wnumber, item.Znumber, item.Uniqproductkey, selected)
		}
	}
	return uniqKeys
}

func orderSendCode(uniqKey string) error {
	url := fmt.Sprintf("%v/web/common/verify-code/get?mobile=%v&smsKey=ORDER_CODE&uniqProductKey=%v", HOST, Phone, uniqKey)
	resp := &BaseResponse{}
	if err := HttpSend(url, "GET", nil, resp); err != nil {
		log.Printf("orderSendCode err:%v", err)
		return err
	}
	if resp.Rescode != 0 {
		log.Printf("orderSendCode !=0 resp=%+v", resp)
		return errors.New(resp.Msg)
	}
	return nil
}

type orderBody struct {
	Hoscode        string `json:"hosCode"`
	Firstdeptcode  string `json:"firstDeptCode"`
	Seconddeptcode string `json:"secondDeptCode"`
	Dutytime       int    `json:"dutyTime"`
	Treatmentday   string `json:"treatmentDay"`
	Uniqproductkey string `json:"uniqProductKey"`
	Cardtype       string `json:"cardType"`
	Cardno         string `json:"cardNo"`
	Smscode        string `json:"smsCode"`
	Hospitalcardid string `json:"hospitalCardId"`
	Phone          string `json:"phone"`
	Orderfrom      string `json:"orderFrom"`
}

type orderResp struct {
	BaseResponse
	Data struct {
		Orderno string `json:"orderNo"`
		Lineup  bool   `json:"lineup"`
	} `json:"data"`
}

func orderSave(uniqKey, smsCode string) (string, error) {
	url := fmt.Sprintf("%v/web/order/save", HOST)
	body := &orderBody{
		Hoscode:        Hoscode,
		Firstdeptcode:  Firstdeptcode,
		Seconddeptcode: Seconddeptcode,
		Dutytime:       0,
		Treatmentday:   Target,
		Uniqproductkey: uniqKey,
		Cardtype:       CardType,
		Cardno:         CardID,
		Smscode:        smsCode,
		Hospitalcardid: "",
		Phone:          Phone,
		Orderfrom:      "HOSP",
	}
	resp := &orderResp{}
	if err := HttpSend(url, "POST", body, resp); err != nil {
		log.Printf("orderSave err:%v", err)
		return "", err
	}
	if resp.Rescode != 0 {
		log.Printf("orderSave rescode!=0 resp=%+v", resp)
		return "", errors.New(resp.Msg)
	}
	return resp.Data.Orderno, nil
}

type orderDetailResp struct {
	BaseResponse
	Data struct {
		Orderno         string      `json:"orderNo"`
		Identifyingcode string      `json:"identifyingCode"`
		Orderstatus     string      `json:"orderStatus"`
		Orderstatusview string      `json:"orderStatusView"`
		Ordertype       string      `json:"orderType"`
		Ordertime       interface{} `json:"orderTime"`
		Cancancel       bool        `json:"canCancel"`
		Canceltype      interface{} `json:"cancelType"`
		Canceltime      interface{} `json:"cancelTime"`
		Orderbaseinfo   interface{} `json:"orderBaseInfo"`
		Patientinfo     interface{} `json:"patientInfo"`
		Payinfo         interface{} `json:"payInfo"`
	} `json:"data"`
}

func orderDetail(orderNum string) error {
	url := fmt.Sprintf("%v/web/order/detail?hosCode=%v&orderNo=%v", HOST, Hoscode, orderNum)
	resp := &orderDetailResp{}
	if err := HttpSend(url, "GET", nil, resp); err != nil {
		log.Printf("orderDetail err:%v", err)
		return err
	}
	if resp.Rescode != 0 {
		log.Printf("orderDetail rescode!=0 resp=%+v", resp)
		return errors.New(resp.Msg)
	}
	log.Printf("%v", resp.Data.Orderstatusview)
	//// TODO
	//if resp.Data.Orderstatus != "TODO"{
	//	return errors.New(resp.Data.Orderstatusview)
	//}
	return nil
}

func main() {
	//fmt.Printf("输入手机号：")
	//var phone string
	//fmt.Scanln(&phone)
	if err := sendCode(Phone); err != nil {
		return
	}

	fmt.Printf("输入验证码：")
	var code string
	fmt.Scanln(&code)
	if err := verifyCode(Phone, code); err != nil {
		return
	}
	log.Printf("登陆成功")
	log.Printf("拉取所有号源")
	var details []DetailData
	var count int
	for {
		count++
		var err error
		details, err = detail(Firstdeptcode, Seconddeptcode, Hoscode, Target)
		if err == nil && len(details) > 0 {
			break
		}
		log.Printf("拉取号源失败或者未开售，重试次数：%v", count)
		time.Sleep(time.Second)
	}

	uniqKeys := choise(details)
	log.Printf("找到合适的号源：%v个", len(uniqKeys))
	if len(uniqKeys) <= 0 {
		return
	}

	count = 0
	for {
		succ := false
		for _, key := range uniqKeys {
			count++
			log.Printf("尝试预定：%v, 次数：%v", key, count)
			if err := orderSendCode(key); err != nil {
				continue
			}
			fmt.Printf("输入验证码：")
			fmt.Scanln(&code)
			orderNum, err := orderSave(key, code)
			if err != nil {
				continue
			}
			if err := orderDetail(orderNum); err != nil {
				continue
			}
			succ = true
			break
		}
		if succ {
			break
		}
	}
}
