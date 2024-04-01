package main

import (
	"fmt"
	"path/filepath"
	"strconv"

	"github.com/beego/beego/v2/server/web"
	"github.com/d3vilh/openvpn-ui/lib"
	"github.com/d3vilh/openvpn-ui/models"
	"github.com/d3vilh/openvpn-ui/routers"
	"github.com/d3vilh/openvpn-ui/state"

	"crypto"
	"crypto/x509"
	"io/ioutil"
	"log"
	"time"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	"gopkg.in/alecthomas/kingpin.v2"

	"crypto/ecdsa"
)

var (
	//configDir := flag.String("config", "conf", "Path to config dir")
	configDir = kingpin.Flag("config", "Interface for admin web UI").Default("conf").Envar("CONFIG_DIR").String()

	listenHost        = kingpin.Flag("listen.host", "Interface for admin web UI").Default("0.0.0.0").Envar("WEB_LISTEN_HOST").String()
	listenPort        = kingpin.Flag("listen.port", "Port for admin web UI").Default("8080").Envar("WEB_LISTEN_PORT").Int()
	letsencrypt       = kingpin.Flag("letsencrypt.enable", "enable Let's encrypt").Default("false").Envar("LETSENCRYPT").Bool()
	letsencryptdomain = kingpin.Flag("letsencrypt.domain", "Your host domain name for generation Let's encrypt keys").Default("ovpn.example.com").Envar("LETSENCRYPTDOMAIN").String()
	letsencryptkeys   = kingpin.Flag("letsencrypt.keys", "Path for Let's Encrypt keys").Default("./lekeys").Envar("LETSENCRYPTKEYS").String()
	letsencryptemail  = kingpin.Flag("letsencrypt.email", "Your email for Let's encrypt").Default("ovpn.example.com").Envar("LETSENCRYPTEMAIL").String()
)

func checkAndUpdateCerts(email, domain string) {

	keyFile := *letsencryptkeys + "/privkey.pem"
	certFile := *letsencryptkeys + "/cert.pem"

	// Проверка наличия сертификата и его срока действия.

	if certExistsAndValid(certFile) {
		log.Println("Cert is valid an shouldn't be updated")
		return
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	myUser := MyUser{
		Email: *letsencryptemail,
		key:   privateKey,
	}

	config := lego.NewConfig(&myUser)
	// Здесь указывайте ваш email

	config.CADirURL = lego.LEDirectoryProduction
	config.Certificate.KeyType = certcrypto.RSA2048

	// Создание клиента
	legoClient, err := lego.NewClient(config)
	if err != nil {
		log.Fatal(err)
	}

	// Регистрация пользователя
	reg, err := legoClient.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		log.Fatal(err)
	}

	myUser.Registration = reg
	// Настройка HTTP-челленджа
	err = legoClient.Challenge.SetHTTP01Provider(http01.NewProviderServer("", "80"))
	if err != nil {
		log.Fatal(err)
	}

	// Получение сертификата
	request := certificate.ObtainRequest{
		Domains: []string{*letsencryptdomain},
		Bundle:  true,
	}
	certificates, err := legoClient.Certificate.Obtain(request)
	if err != nil {
		log.Fatal(err)
	}

	// Создание клиента LEGO.
	user := MyUser{Email: email}
	config := lego.NewConfig(&user)
	client, err := lego.NewClient(config)
	if err != nil {
		log.Fatal(err)
	}

	// Регистрация пользователя.
	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		log.Fatal(err)
	}
	user.Registration = reg

	// Настройка HTTP-вызова.
	err = client.Challenge.SetHTTP01Provider(http01.NewProviderServer("", strconv.Itoa(*listenPort)))
	if err != nil {
		log.Fatal(err)
	}

	// Запрос сертификата.
	request := certificate.ObtainRequest{
		Domains: []string{domain},
		Bundle:  true,
	}
	certificates, err := client.Certificate.Obtain(request)
	if err != nil {
		log.Fatal(err)
	}

	// Сохранение сертификата и ключа.
	err = ioutil.WriteFile(certFile, certificates.Certificate, 0600)
	if err != nil {
		log.Fatal(err)
	}
	err = ioutil.WriteFile(keyFile, certificates.PrivateKey, 0600)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Cert updated succesfully")
}

// Проверка наличия и валидности сертификата.
func certExistsAndValid(certPath string) bool {
	certBytes, err := ioutil.ReadFile(certPath)
	if err != nil {
		return false
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return false
	}
	return cert.NotAfter.After(time.Now())
}

// MyUser реализует интерфейс registration.User.
type MyUser struct {
	Email        string
	Registration *registration.Resource
	Key          crypto.PrivateKey
}

func (u *MyUser) GetEmail() string {
	return u.Email
}
func (u MyUser) GetRegistration() *registration.Resource {
	return u.Registration
}
func (u *MyUser) GetPrivateKey() crypto.PrivateKey {
	return u.Key
}

func main() {

	kingpin.Parse()

	configFile := filepath.Join(*configDir, "app.conf")
	fmt.Println("Config file:", configFile)

	if err := web.LoadAppConfig("ini", configFile); err != nil {
		panic(err)
	}

	if *letsencrypt == true {

		// Проверка и обновление сертификата.
		checkAndUpdateCerts(*letsencryptemail, *letsencryptdomain)

		certFile := *letsencryptkeys + "/cert.pem"
		keyFile := *letsencryptkeys + "/privkey.pem"

		// Задайте порт и включите HTTPS
		web.BConfig.Listen.EnableHTTP = false
		web.BConfig.Listen.HTTPSAddr = *listenHost
		web.BConfig.Listen.HTTPSPort = *listenPort
		web.BConfig.Listen.HTTPSKeyFile = keyFile
		web.BConfig.Listen.HTTPSCertFile = certFile
		web.BConfig.Listen.EnableHTTPS = true

	} else {
		web.BConfig.Listen.EnableHTTP = true
		web.BConfig.Listen.EnableHTTPS = false
		web.BConfig.Listen.HTTPAddr = *listenHost
		web.BConfig.Listen.HTTPPort = *listenPort
	}

	models.InitDB()
	models.CreateDefaultUsers()
	defaultSettings, err := models.CreateDefaultSettings()
	if err != nil {
		panic(err)
	}

	models.CreateDefaultOVConfig(*configDir, defaultSettings.OVConfigPath, defaultSettings.MIAddress, defaultSettings.MINetwork)
	models.CreateDefaultOVClientConfig(*configDir, defaultSettings.OVConfigPath, defaultSettings.MIAddress, defaultSettings.MINetwork)
	models.CreateDefaultEasyRSAConfig(*configDir, defaultSettings.EasyRSAPath, defaultSettings.MIAddress, defaultSettings.MINetwork)
	state.GlobalCfg = *defaultSettings

	routers.Init(*configDir)

	lib.AddFuncMaps()
	web.Run()
}
