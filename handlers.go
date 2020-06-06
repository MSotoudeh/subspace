package main

import (
	"fmt"
	"io/ioutil"
	"math"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/julienschmidt/httprouter"
	"golang.org/x/crypto/bcrypt"

	pipes "github.com/ebuchman/go-shell-pipes"
	qrcode "github.com/skip2/go-qrcode"
)

var (
	validEmail         = regexp.MustCompile(`^[ -~]+@[ -~]+$`)
	validPassword      = regexp.MustCompile(`^[ -~]{6,200}$`)
	validString        = regexp.MustCompile(`^[ -~]{1,200}$`)
	maxProfiles        = 250
	maxProfilesPerUser = 10
)

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func ssoHandler(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	if token := samlSP.GetAuthorizationToken(r); token != nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	logger.Debugf("SSO: require account handler")
	samlSP.RequireAccountHandler(w, r)
}

func samlHandler(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	if samlSP == nil {
		logger.Warnf("SAML is not configured")
		http.NotFound(w, r)
		return
	}
	logger.Debugf("SSO: samlSP.ServeHTTP")
	samlSP.ServeHTTP(w, r)
}

func wireguardQRConfigHandler(w *Web) {
	profile, err := config.FindProfile(w.ps.ByName("profile"))
	if err != nil {
		http.NotFound(w.w, w.r)
		return
	}
	if !w.Admin && profile.UserID != w.User.ID {
		Error(w.w, fmt.Errorf("failed to view config: permission denied"))
		return
	}

	b, err := ioutil.ReadFile(profile.WireGuardConfigPath())
	if err != nil {
		Error(w.w, err)
		return
	}

	img, err := qrcode.Encode(string(b), qrcode.Medium, 256)
	if err != nil {
		Error(w.w, err)
		return
	}

	w.w.Header().Set("Content-Type", "image/png")
	w.w.Header().Set("Content-Length", fmt.Sprintf("%d", len(img)))
	if _, err := w.w.Write(img); err != nil {
		Error(w.w, err)
		return
	}
}

func wireguardConfigHandler(w *Web) {
	profile, err := config.FindProfile(w.ps.ByName("profile"))
	if err != nil {
		http.NotFound(w.w, w.r)
		return
	}
	if !w.Admin && profile.UserID != w.User.ID {
		Error(w.w, fmt.Errorf("failed to view config: permission denied"))
		return
	}

	b, err := ioutil.ReadFile(profile.WireGuardConfigPath())
	if err != nil {
		Error(w.w, err)
		return
	}

	w.w.Header().Set("Content-Disposition", "attachment; filename="+profile.WireGuardConfigName())
	w.w.Header().Set("Content-Type", "application/x-wireguard-profile")
	w.w.Header().Set("Content-Length", fmt.Sprintf("%d", len(b)))
	if _, err := w.w.Write(b); err != nil {
		Error(w.w, err)
		return
	}
}

func configureHandler(w *Web) {
	if config.FindInfo().Configured {
		w.Redirect("/?error=configured")
		return
	}

	if w.r.Method == "GET" {
		w.HTML()
		return
	}

	email := strings.ToLower(strings.TrimSpace(w.r.FormValue("email")))
	emailConfirm := strings.ToLower(strings.TrimSpace(w.r.FormValue("email_confirm")))
	password := w.r.FormValue("password")

	if !validEmail.MatchString(email) || !validPassword.MatchString(password) || email != emailConfirm {
		w.Redirect("/configure?error=invalid")
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		w.Redirect("/forgot?error=bcrypt")
		return
	}
	config.UpdateInfo(func(i *Info) error {
		i.Email = email
		i.Password = hashedPassword
		i.Configured = true
		return nil
	})

	if err := w.SigninSession(true, ""); err != nil {
		Error(w.w, err)
		return
	}
	w.Redirect("/settings?success=configured")
}

func forgotHandler(w *Web) {
	if w.r.Method == "GET" {
		w.HTML()
		return
	}

	email := strings.ToLower(strings.TrimSpace(w.r.FormValue("email")))
	secret := w.r.FormValue("secret")
	password := w.r.FormValue("password")

	if email != "" && !validEmail.MatchString(email) {
		w.Redirect("/forgot?error=invalid")
		return
	}
	if secret != "" && !validString.MatchString(secret) {
		w.Redirect("/forgot?error=invalid")
		return
	}
	if email != "" && secret != "" && !validPassword.MatchString(password) {
		w.Redirect("/forgot?error=invalid&email=%s&secret=%s", email, secret)
		return
	}

	if email != config.FindInfo().Email {
		w.Redirect("/forgot?error=invalid")
		return
	}

	if secret == "" {
		secret = config.FindInfo().Secret
		if secret == "" {
			secret = RandomString(32)
			config.UpdateInfo(func(i *Info) error {
				if i.Secret == "" {
					i.Secret = secret
				}
				return nil
			})
		}

		go func() {
			if err := mailer.Forgot(email, secret); err != nil {
				logger.Error(err)
			}
		}()

		w.Redirect("/forgot?success=forgot")
		return
	}

	if secret != config.FindInfo().Secret {
		w.Redirect("/forgot?error=invalid")
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		w.Redirect("/forgot?error=bcrypt")
		return
	}
	config.UpdateInfo(func(i *Info) error {
		i.Password = hashedPassword
		i.Secret = ""
		return nil
	})

	if err := w.SigninSession(true, ""); err != nil {
		Error(w.w, err)
		return
	}
	w.Redirect("/")
}

func signoutHandler(w *Web) {
	w.SignoutSession()
	w.Redirect("/signin")
}

func signinHandler(w *Web) {
	if w.r.Method == "GET" {
		w.HTML()
		return
	}

	email := strings.ToLower(strings.TrimSpace(w.r.FormValue("email")))
	password := w.r.FormValue("password")

	if email != config.FindInfo().Email {
		w.Redirect("/signin?error=invalid")
		return
	}

	if err := bcrypt.CompareHashAndPassword(config.FindInfo().Password, []byte(password)); err != nil {
		w.Redirect("/signin?error=invalid")
		return
	}
	if err := w.SigninSession(true, ""); err != nil {
		Error(w.w, err)
		return
	}

	w.Redirect("/")
}

func userEditHandler(w *Web) {
	userID := w.ps.ByName("user")
	if userID == "" {
		userID = w.r.FormValue("user")
	}
	user, err := config.FindUser(userID)
	if err != nil {
		http.NotFound(w.w, w.r)
		return
	}
	if !w.Admin {
		Error(w.w, fmt.Errorf("failed to edit user: permission denied"))
		return
	}

	if w.r.Method == "GET" {
		w.TargetUser = user
		w.Profiles = config.ListProfilesByUser(user.ID)
		w.HTML()
		return
	}

	if w.User.ID == user.ID {
		w.Redirect("/user/edit/%s", user.ID)
		return
	}

	admin := w.r.FormValue("admin") == "yes"

	config.UpdateUser(user.ID, func(u *User) error {
		u.Admin = admin
		return nil
	})

	w.Redirect("/user/edit/%s?success=edituser", user.ID)
}

func userDeleteHandler(w *Web) {
	userID := w.ps.ByName("user")
	if userID == "" {
		userID = w.r.FormValue("user")
	}
	user, err := config.FindUser(userID)
	if err != nil {
		http.NotFound(w.w, w.r)
		return
	}
	if !w.Admin {
		Error(w.w, fmt.Errorf("failed to delete user: permission denied"))
		return
	}
	if w.User.ID == user.ID {
		w.Redirect("/user/edit/%s?error=deleteuser", user.ID)
		return
	}

	if w.r.Method == "GET" {
		w.TargetUser = user
		w.HTML()
		return
	}

	for _, profile := range config.ListProfilesByUser(user.ID) {
		if err := deleteProfile(profile); err != nil {
			logger.Errorf("delete profile failed: %s", err)
			w.Redirect("/profile/delete?error=deleteprofile")
			return
		}
	}

	if err := config.DeleteUser(user.ID); err != nil {
		Error(w.w, err)
		return
	}
	w.Redirect("/?success=deleteuser")
}

func profileAddHandler(w *Web) {
	if !w.Admin && w.User.ID == "" {
		http.NotFound(w.w, w.r)
		return
	}

	name := strings.TrimSpace(w.r.FormValue("name"))
	platform := strings.TrimSpace(w.r.FormValue("platform"))
	routing := strings.TrimSpace(w.r.FormValue("routing"))
	admin := w.r.FormValue("admin") == "yes"

	cmd2, err := pipes.RunString("rm /data/wireguard/private.key && rm /data/wireguard/public.key")
	_ = cmd2

	cmd, err := pipes.RunString("wg genkey | tee /data/wireguard/private.key | wg pubkey | tee /data/wireguard/public.key")
	_ = cmd

	if err != nil {
		fmt.Printf("error is %s\n", err)
	}

	privatekey_str, err := ioutil.ReadFile("/data/wireguard/private.key")
	publickey_str, err := ioutil.ReadFile("/data/wireguard/public.key")

	privatekey := string(privatekey_str)
	publickey := string(publickey_str)
	privatekey = strings.TrimSuffix(privatekey, "\n")
	publickey = strings.TrimSuffix(publickey, "\n")

	if platform == "" {
		platform = "other"
	}

	//Set routing to "any" if not choosen during creation
	if routing == "" || len(routing) == 0 {
		routing = "any"
	}

	if name == "" {
		w.Redirect("/?error=profilename")
		return
	}

	// Check if profile name is already used
	if _, err := os.Stat("/data/wireguard/clients/" + name); !os.IsNotExist(err) {
		w.Redirect("/?error=profileexists")
		return
	}
	if _, err := os.Stat("/data/wireguard/peers/" + name); !os.IsNotExist(err) {
		w.Redirect("/?error=profileexists")
		return
	}

	var userID string
	if admin {
		userID = ""
	} else {
		userID = w.User.ID
	}

	if !admin {
		if len(config.ListProfilesByUser(userID)) >= maxProfilesPerUser {
			w.Redirect("/?error=addprofile")
			return
		}
	}

	if len(config.ListProfiles()) >= maxProfiles {
		w.Redirect("/?error=addprofile")
		return
	}

	profile, err := config.AddProfile(userID, privatekey, publickey, name, platform, routing)
	if err != nil {
		logger.Warn(err)
		w.Redirect("/?error=addprofile")
		return
	}

	ipv4Pref := "10.99.97."
	if pref := getEnv("SUBSPACE_IPV4_PREF", "nil"); pref != "nil" {
		ipv4Pref = pref
	}
	ipv4Gw := "10.99.97.1"
	if gw := getEnv("SUBSPACE_IPV4_GW", "nil"); gw != "nil" {
		ipv4Gw = gw
	}
	ipv4Cidr := "24"
	if cidr := getEnv("SUBSPACE_IPV4_CIDR", "nil"); cidr != "nil" {
		ipv4Cidr = cidr
	}
	ipv6Pref := "fd00::10:97:"
	if pref := getEnv("SUBSPACE_IPV6_PREF", "nil"); pref != "nil" {
		ipv6Pref = pref
	}
	ipv6Gw := "fd00::10:97:1"
	if gw := getEnv("SUBSPACE_IPV6_GW", "nil"); gw != "nil" {
		ipv6Gw = gw
	}
	ipv6Cidr := "64"
	if cidr := getEnv("SUBSPACE_IPV6_CIDR", "nil"); cidr != "nil" {
		ipv6Cidr = cidr
	}
	listenport := "51820"
	if port := getEnv("SUBSPACE_LISTENPORT", "nil"); port != "nil" {
		listenport = port
	}
	endpointHost := httpHost
	if eh := getEnv("SUBSPACE_ENDPOINT_HOST", "nil"); eh != "nil" {
		endpointHost = eh
	}
	//Checks to handle different scenarios
	allowedips := "0.0.0.0/0, ::/0"
	if ips := getEnv("SUBSPACE_ALLOWED_IPS", "nil"); ips != "nil" {
		if routing == "lan" {
			allowedips = ips
		} else if routing == "any" {
			allowedips = "0.0.0.0/0, ::/0"
		}
	} else if routing == "" || len(routing) == 0 {
		allowedips = "0.0.0.0/0, ::/0"
	}

	script := `
cd {{$.Datadir}}/wireguard
wg_private_key={{$.Profile.Private_Key}}
wg_public_key={{$.Profile.Public_Key}}

wg set wg0 peer ${wg_public_key} allowed-ips {{$.IPv4Pref}}{{$.Profile.Number}}/32,{{$.IPv6Pref}}{{$.Profile.Number}}/128

mkdir peers/{{$.Profile.Name}}
cat <<WGPEER >peers/{{$.Profile.Name}}/{{$.Profile.ID}}.conf
[Peer]
PublicKey = ${wg_public_key}
AllowedIPs = {{$.IPv4Pref}}{{$.Profile.Number}}/32,{{$.IPv6Pref}}{{$.Profile.Number}}/128
PersistentKeepalive = 25
WGPEER

mkdir clients/{{$.Profile.Name}}
cat <<WGCLIENT >clients/{{$.Profile.Name}}/{{$.Profile.ID}}.conf
[Interface]
PrivateKey = ${wg_private_key}
DNS = {{$.IPv4Gw}}, {{$.IPv6Gw}}
Address = {{$.IPv4Pref}}{{$.Profile.Number}}/{{$.IPv4Cidr}},{{$.IPv6Pref}}{{$.Profile.Number}}/{{$.IPv6Cidr}}

[Peer]
PublicKey = $(cat server/server.public)

Endpoint = {{$.EndpointHost}}:{{$.Listenport}}
AllowedIPs = {{$.AllowedIPS}}
WGCLIENT
`
	_, err = bash(script, struct {
		Profile      Profile
		EndpointHost string
		Datadir      string
		IPv4Gw       string
		IPv6Gw       string
		IPv4Pref     string
		IPv6Pref     string
		IPv4Cidr     string
		IPv6Cidr     string
		Listenport   string
		AllowedIPS   string
	}{
		profile,
		endpointHost,
		datadir,
		ipv4Gw,
		ipv6Gw,
		ipv4Pref,
		ipv6Pref,
		ipv4Cidr,
		ipv6Cidr,
		listenport,
		allowedips,
	})
	if err != nil {
		logger.Warn(err)
		f, _ := os.Create("/tmp/error.txt")
		errstr := fmt.Sprintln(err)
		f.WriteString(errstr)
		w.Redirect("/?error=addprofile")
		return
	}

	w.Redirect("/profile/connect/%s?success=addprofile", profile.ID)
}

func profileConnectHandler(w *Web) {
	profile, err := config.FindProfile(w.ps.ByName("profile"))
	if err != nil {
		http.NotFound(w.w, w.r)
		return
	}
	if !w.Admin && profile.UserID != w.User.ID {
		Error(w.w, fmt.Errorf("failed to view profile: permission denied"))
		return
	}
	w.Profile = profile
	w.HTML()
}

func profileDeleteHandler(w *Web) {
	profileID := w.ps.ByName("profile")
	if profileID == "" {
		profileID = w.r.FormValue("profile")
	}
	profile, err := config.FindProfile(profileID)
	if err != nil {
		http.NotFound(w.w, w.r)
		return
	}
	if !w.Admin && profile.UserID != w.User.ID {
		Error(w.w, fmt.Errorf("failed to delete profile: permission denied"))
		return
	}

	if w.r.Method == "GET" {
		w.Profile = profile
		w.HTML()
		return
	}
	if err := deleteProfile(profile); err != nil {
		logger.Errorf("delete profile failed: %s", err)
		w.Redirect("/profile/delete?error=deleteprofile")
		return
	}
	if profile.UserID != "" {
		w.Redirect("/user/edit/%s?success=deleteprofile", profile.UserID)
		return
	}
	w.Redirect("/?success=deleteprofile")
}

func indexHandler(w *Web) {
	if w.User.ID != "" {
		w.TargetProfiles = config.ListProfilesByUser(w.User.ID)
	}
	if w.Admin {
		w.Profiles = config.ListProfilesByUser("")
		w.Users = config.ListUsers()
	} else {
		w.Profiles = config.ListProfilesByUser(w.User.ID)
	}
	w.HTML()
}

func RoundUp(input float64, places int) (newVal float64) {
	var round float64
	pow := math.Pow(10, float64(places))
	digit := pow * input
	round = math.Ceil(digit)
	newVal = round / pow
	return
}

func ByteFormat(inputNum float64, precision int) string {

	if precision <= 0 {
		precision = 1
	}

	var unit string
	var returnVal float64

	if inputNum >= 1000000000000 {
		returnVal = RoundUp((inputNum / 1099511627776), precision)
		unit = " TiB" // terrabyte
	} else if inputNum >= 1000000000 {
		returnVal = RoundUp((inputNum / 1073741824), precision)
		unit = " GiB" // gigabyte
	} else if inputNum >= 1000000 {
		returnVal = RoundUp((inputNum / 1048576), precision)
		unit = " MiB" // megabyte
	} else if inputNum >= 1000 {
		returnVal = RoundUp((inputNum / 1024), precision)
		unit = " KiB" // kilobyte
	} else {
		returnVal = inputNum
		unit = " B" // byte
	}

	return strconv.FormatFloat(returnVal, 'f', precision, 64) + unit
}

func TimeDiff(a, b time.Time) (year, month, day, hour, min, sec int) {
	if a.Location() != b.Location() {
		b = b.In(a.Location())
	}
	if a.After(b) {
		a, b = b, a
	}
	y1, M1, d1 := a.Date()
	y2, M2, d2 := b.Date()

	h1, m1, s1 := a.Clock()
	h2, m2, s2 := b.Clock()

	year = int(y2 - y1)
	month = int(M2 - M1)
	day = int(d2 - d1)
	hour = int(h2 - h1)
	min = int(m2 - m1)
	sec = int(s2 - s1)

	// Normalize negative values
	if sec < 0 {
		sec += 60
		min--
	}
	if min < 0 {
		min += 60
		hour--
	}
	if hour < 0 {
		hour += 24
		day--
	}
	if day < 0 {
		// days in month:
		t := time.Date(y1, M1, 32, 0, 0, 0, 0, time.UTC)
		day += 32 - t.Day()
		month--
	}
	if month < 0 {
		month += 12
		year--
	}

	return
}

func Short(s string, i int) string {
	runes := []rune(s)
	if len(runes) > i {
		return string(runes[:i])
	}
	return s
}

func statusHandler(w *Web) {
	wg_dump, err := exec.Command("wg", "show", "all", "dump").Output()
	if err != nil {
		fmt.Printf("error is %s\n", err)
	}
	wg_dump_str := string(wg_dump)
	split_line := strings.Split(wg_dump_str, "\n")

	var split_tab []string
	var AllowedIP_split []string
	var ok bool
	var Datas []Data
	var HandshakeStatus string
	//domain := config.Info.Domain

	for i := 0; i < (len(split_line) - 1); i++ {

		split_tab = strings.Split(split_line[i], "\t")
		if len(split_tab) < 9 && ok != true {

			for j := 0; j < 1; j++ {
				if ok != true {
					Datas = []Data{
						Data{
							Type:        "Server",
							Name:        split_tab[0],
							Domain:      httpHost,
							Private_Key: split_tab[1],
							Public_Key:  split_tab[2],
							Port:        split_tab[3],
						},
					}
				}
				ok = true
			}
		}
		if len(split_tab) == 9 {
			rx, _ := strconv.ParseFloat(strings.TrimSpace(split_tab[6]), 64)
			tx, _ := strconv.ParseFloat(strings.TrimSpace(split_tab[7]), 64)
			Latest_handshake_int, err := strconv.ParseInt(split_tab[5], 10, 64)
			if err != nil {
				panic(err)
			}
			Latest_handshake_Time := time.Unix(Latest_handshake_int, 0)
			year, month, day, hour, min, sec := TimeDiff(Latest_handshake_Time, time.Now())

			if year == 0 && month != 0 {
				HandshakeStatus = fmt.Sprintf("%d months, %d days, %d hours, %d mins and %d seconds ago\n",
					month, day, hour, min, sec)
			} else if year == 0 && month == 0 && day != 0 {
				HandshakeStatus = fmt.Sprintf("%d days, %d hours, %d mins and %d seconds ago\n",
					day, hour, min, sec)
			} else if year == 0 && month == 0 && day == 0 && hour != 0 {
				HandshakeStatus = fmt.Sprintf("%d hours, %d mins and %d seconds ago\n",
					hour, min, sec)
			} else if year == 0 && month == 0 && day == 0 && hour == 0 && min != 0 {
				HandshakeStatus = fmt.Sprintf("%d mins and %d seconds ago\n",
					min, sec)
			} else if year == 0 && month == 0 && day == 0 && hour == 0 && min == 0 && sec != 0 {
				HandshakeStatus = fmt.Sprintf("%d seconds ago\n",
					sec)
			} else {
				HandshakeStatus = fmt.Sprintf("No handshake yet\n")
			}

			AllowedIP_split = strings.Split(split_tab[4], ",")
			// fmt.Println(AllowedIlP_split)
			// for ip := 0; ip < (len(AllowedIP_split)); ip++ {
			// 	fmt.Printf(AllowedIP_split[ip])
			// }

			Dataz :=
				Data{
					Type:             "Peer",
					Name:             split_tab[0],
					Public_Key:       split_tab[1],
					Public_Key_Trim:  Short(split_tab[1], 6),
					Preshared_Key:    split_tab[2],
					ClientEndpoint:   split_tab[3],
					Allowed:          split_tab[4],
					AllowedIPs:       AllowedIP_split,
					Latest_handshake: HandshakeStatus,
					Transfer_rx:      ByteFormat(rx, 2),
					Transfer_tx:      ByteFormat(tx, 2),
					Keepalive:        split_tab[8],
				}
			Datas = append(Datas, Dataz)
		}
	}
	profiles := config.ListProfiles()
	w.Statuses = Datas
	w.Profiles = profiles
	w.HTML()
}

func settingsHandler(w *Web) {
	if !w.Admin {
		Error(w.w, fmt.Errorf("settings: permission denied"))
		return
	}

	if w.r.Method == "GET" {
		w.HTML()
		return
	}

	email := strings.ToLower(strings.TrimSpace(w.r.FormValue("email")))
	samlMetadata := strings.TrimSpace(w.r.FormValue("saml_metadata"))

	currentPassword := w.r.FormValue("current_password")
	newPassword := w.r.FormValue("new_password")

	config.UpdateInfo(func(i *Info) error {
		i.SAML.IDPMetadata = samlMetadata
		i.Email = email
		return nil
	})

	// Configure SAML if metadata is present.
	if len(samlMetadata) > 0 {
		if err := configureSAML(); err != nil {
			logger.Warnf("configuring SAML failed: %s", err)
			w.Redirect("/settings?error=saml")
		}
	} else {
		samlSP = nil
	}

	if currentPassword != "" || newPassword != "" {
		if !validPassword.MatchString(newPassword) {
			w.Redirect("/settings?error=invalid")
			return
		}

		if err := bcrypt.CompareHashAndPassword(config.FindInfo().Password, []byte(currentPassword)); err != nil {
			w.Redirect("/settings?error=invalid")
			return
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
		if err != nil {
			w.Redirect("/settings?error=bcrypt")
			return
		}

		config.UpdateInfo(func(i *Info) error {
			i.Password = hashedPassword
			return nil
		})
	}

	w.Redirect("/settings?success=settings")
}

func helpHandler(w *Web) {
	w.HTML()
}

//
// Helpers
//
func deleteProfile(profile Profile) error {
	script := `
# WireGuard
cd {{$.Datadir}}/wireguard
peerid=$(cat peers/{{$.Profile.Name}}/{{$.Profile.ID}}.conf | perl -ne 'print $1 if /PublicKey\s*=\s*(.*)/')
wg set wg0 peer $peerid remove
rm peers/{{$.Profile.Name}}/{{$.Profile.ID}}.conf
rm clients/{{$.Profile.Name}}/{{$.Profile.ID}}.conf
rm clients/{{$.Profile.Name}}/{{$.Profile.ID}}.png
rm -rf peers/{{$.Profile.Name}}
rm -rf clients/{{$.Profile.Name}}
`
	output, err := bash(script, struct {
		Datadir string
		Profile Profile
	}{
		datadir,
		profile,
	})
	if err != nil {
		return fmt.Errorf("delete profile failed %s %s", err, output)
	}
	return config.DeleteProfile(profile.ID)
}

func emailsettingsHandler(w *Web) {
	if w.r.Method == "GET" {
		w.HTML()
		return
	}

	from := strings.ToLower(strings.TrimSpace(w.r.FormValue("from")))
	server := strings.ToLower(strings.TrimSpace(w.r.FormValue("server")))
	port := w.r.FormValue("port")
	username := strings.ToLower(strings.TrimSpace(w.r.FormValue("username")))
	password := w.r.FormValue("password")

	int_port, err := strconv.Atoi(port)
	if err != nil {
		fmt.Println(err)
	}

	if from != "" || server != "" || port != "" || username != "" || password != "" {
		if err != nil {
			w.Redirect("/emailsettings?error=emptywrongtype")
			return
		}
	}

	config.UpdateInfo(func(i *Info) error {
		i.Mail.From = from
		i.Mail.Server = server
		i.Mail.Port = int_port
		i.Mail.Username = username
		i.Mail.Password = password
		return nil
	})

	w.Redirect("/?success=emailsettings")
}
