package main

import (
	"fmt"
	"strings"
	"os"
	"runtime"
	"strconv"
	"os/exec"
	"net/http"
	"crypto/tls"
	"net/url"
	"io"
	"reflect"
	"time"
	"encoding/json"
)

type User struct {
    Password string `json:"password"`
    Username string `json:"username"`
}

type passwordJson struct {
    Users []User `json:"users"`
}

func getLocalUsers() []string {
	if runtime.GOOS == "linux" {
		users := []string{}
		file, _ := os.ReadFile("/etc/passwd")
		for _, user := range strings.Split(string(file), "\n") {
			tokens := strings.Split(string(user), ":")
			if len(tokens) > 2 {
				username := tokens[0]
				uid, _ := strconv.Atoi(tokens[2])
				if ((uid >= 1000 || username == "root") && username != "nobody") {
					users = append(users, username)
				}
			}
		}
		return users
	} else {
		cmd := exec.Command("powershell.exe", "-c", "(get-localuser).name")
		output, _ := cmd.Output()
		users := strings.Split(string(output), "\r\n")
		new_users := []string{}

		// Get rid of computer accounts on AD, which contain $
		for _, user := range users {
			if !strings.Contains(user, "$") {
				new_users = append(new_users, user)
			}
		}
		return new_users
	}
}

// Source - https://stackoverflow.com/a
// Posted by peterwilliams97, modified by community. See post 'Timeline' for change history
// Retrieved 2025-12-11, License - CC BY-SA 4.0

// difference returns the elements in `a` that aren't in `b`.
func difference(a, b []string) []string {
    mb := make(map[string]struct{}, len(b))
    for _, x := range b {
        mb[x] = struct{}{}
    }
    var diff []string
    for _, x := range a {
        if _, found := mb[x]; !found {
            diff = append(diff, x)
        }
    }
    return diff
}


// func (p *program) run() {
// 	// put main code here when turning it into a service
// }

// func (p *program) Stop(s service.Service) error {
// 	return nil
// }

func main() {
	// svcConfig := &service.Config{
	// 	Name:        "MyService",
	// 	DisplayName: "MyDisplayNameService",
	// 	Description: "Da Service",
	// }

	// prg := &program{}
	// s, _ := service.New(prg, svcConfig)
	// s.Run()
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	
	is_dc := false
	local_ip := "1.1.1.1"
	if runtime.GOOS == "linux" {
		cmd := exec.Command("hostname", "-I")
		output, _ := cmd.Output()
		local_ip = strings.Split(string(output), " ")[0]
	} else {
		cmd := exec.Command("powershell.exe", "-c", "(Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -like \"*Ethernet*\" }).IPAddress")
		output, _ := cmd.Output()
		local_ip = string(output)
		cmd = exec.Command("powershell.exe", "-c", "Get-WmiObject -Query 'select * from Win32_OperatingSystem where (ProductType = \"2\")'")
		output, _ = cmd.Output()
		fmt.Println(len(output))
		if len(output) != 0 {
			is_dc = true
		}
	}
	if is_dc {
		fmt.Println("hi")
	}

	server_ip_address := "127.0.0.1"

	form := url.Values{}
	form.Add("ip_address", local_ip)

	resp, _ := http.PostForm("https://" + server_ip_address + "/register_client",form)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	token := string(body)

	local_users := getLocalUsers()
	i := 0

	form = url.Values{}
	form.Add("ip_address", local_ip)
	form.Add("local_users", strings.Join(local_users, ","))
	form.Add("authoriztion_token", token)

	resp, _ = http.PostForm("https://" + server_ip_address + "/update_local_users",form)

	for {
		i += 1
		if i % 10 == 0 {
			new_local_user_list := getLocalUsers()
			if !reflect.DeepEqual(new_local_user_list, local_users) {
				diff := difference(new_local_user_list, local_users)
				
				local_users = new_local_user_list

				form = url.Values{}
				form.Add("ip_address", local_ip)
				form.Add("local_users", strings.Join(diff, ","))
				form.Add("authoriztion_token", token)

				resp, _ = http.PostForm("https://" + server_ip_address + "/update_local_users",form)
			}
		}

		form = url.Values{}
		form.Add("ip_address", local_ip)
		form.Add("authoriztion_token", token)

		resp, _ = http.PostForm("https://" + server_ip_address + "/get_passwords_to_claim",form)
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		
		if len(body) != 0 {
			var userPasswords passwordJson
			json.Unmarshal(body, &userPasswords)
			for _, userToChangePassword := range userPasswords.Users {
				fmt.Println(userToChangePassword.Username)
				fmt.Println(userToChangePassword.Password)
			}
		}

		time.Sleep(5 * time.Second)
	}
}
