package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"time"
	"log"
)

// Global variables (package-level)
var (
	Chpasswd_path = "/usr/sbin/chpasswd"
	Usermod_path  = "/usr/sbin/usermod"
	Gpasswd_path  = "/usr/sbin/gpasswd"
	Useradd_path  = "/usr/sbin/useradd"
)

type UserPasswordChangeStatus struct {
	Status   string `json:"status"`
	Username string `json:"username"`
}

type User struct {
	Password string `json:"password"`
	Username string `json:"username"`
	Enabled  bool   `json:"enabled"`
	Admin    bool   `json:"admin"`
}

type passwordJson struct {
	Users []User `json:"users"`
}

type localUserJson struct {
	User    string `json:"user"`
	Enabled bool   `json:"enabled"`
	Admin   bool   `json:"admin"`
}

func setLocalBinaries() {
	if runtime.GOOS == "linux" {
		path, err := exec.LookPath("usermod")
		if err == nil {
			Usermod_path = path
			println("Found usermod at:", path)
		}
		path, err = exec.LookPath("gpasswd")
		if err == nil {
			Gpasswd_path = path
			println("Found gpasswd at:", path)
		}
		path, err = exec.LookPath("useradd")
		if err == nil {
			Useradd_path = path
			println("Found useradd at:", path)
		}
		path, err = exec.LookPath("chpasswd")
		if err == nil {
			Chpasswd_path = path
			println("Found chpasswd at:", path)
		}
	}
}

func getLocalUsers(is_dc bool) string {
	if runtime.GOOS == "linux" {
		users := []localUserJson{}
		file, _ := os.ReadFile("/etc/passwd")
		group_file, _ := os.ReadFile("/etc/group")
		sudo_group := ""
		for _, group := range strings.Split(string(group_file), "\n") {
			tokens := strings.Split(string(group), ":")
			if tokens[0] == "sudo" || tokens[0] == "wheel" {
				sudo_group = tokens[3]
				break
			}
		}
		for _, user := range strings.Split(string(file), "\n") {
			tokens := strings.Split(string(user), ":")
			if len(tokens) > 2 {
				username := tokens[0]
				uid, _ := strconv.Atoi(tokens[2])
				if (uid >= 1000 || username == "root") && username != "nobody" {
					enabled := true
					if tokens[6] == "/usr/sbin/nologin" || tokens[6] == "/bin/false" {
						enabled = false
					}
					is_admin := false
					if sudo_group != "" {
						sudo_users := strings.Split(sudo_group, ",")
						for _, sudo_user := range sudo_users {
							if sudo_user == username || username == "root" {
								is_admin = true
								break
							}
						}
					}
					users = append(users, localUserJson{User: username, Enabled: enabled, Admin: is_admin})
				}
			}
		}
		jsonData, _ := json.Marshal(users)
		return string(jsonData)
	} else {
		user_cmd_to_run := ""
		admin_user_cmd_to_run := ""
		if is_dc {
			user_cmd_to_run = "Get-ADUser -Filter * | select-object name, enabled | format-table -hideTableHeaders"
			admin_user_cmd_to_run = "Get-ADGroupMember -Identity \"Domain Admins\" | Select-Object name | format-table -hideTableHeaders"
		} else {
			user_cmd_to_run = "get-localuser | select-object name, enabled | format-table -hideTableHeaders"
			admin_user_cmd_to_run = "Get-LocalGroupMember \"Administrators\" | select-object name | format-table -hideTableHeaders"
		}

		cmd := exec.Command("powershell.exe", "-NoProfile", "-C", user_cmd_to_run)
		output, _ := cmd.CombinedOutput()
		users := strings.Split(string(output), "\r\n")

		cmd = exec.Command("powershell.exe", "-NoProfile", "-C", admin_user_cmd_to_run)
		output, _ = cmd.CombinedOutput()
		admin_users_list := strings.Split(string(output), "\r\n")

		local_users := []localUserJson{}

		// Get rid of computer accounts on AD, which contain $
		for _, user := range users {
			if !strings.Contains(user, "$") && len(strings.TrimSpace(user)) > 0 {
				tokens := strings.Fields(user)
				user := tokens[0]
				enabled := tokens[1]
				enabled = strings.TrimSpace(enabled)
				enabled = strings.ToLower(enabled)
				enabled_val := false
				if enabled == "true" {
					enabled_val = true
				} else {
					enabled_val = false
				}

				is_admin := false
				for _, admin_user := range admin_users_list {
					admin_user = strings.TrimSpace(admin_user)
					if strings.Contains(admin_user, user) {
						is_admin = true
						break
					}
				}

				local_users = append(local_users, localUserJson{User: user, Enabled: enabled_val, Admin: is_admin})
			}
		}
		jsonData, _ := json.Marshal(local_users)
		return string(jsonData)
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

func getLocalIP() string {
	if runtime.GOOS == "linux" {
		cmd := exec.Command("hostname", "-I")
		output, _ := cmd.CombinedOutput()
		return strings.Split(string(output), " ")[0]
	} else {
		cmd := exec.Command("powershell.exe", "-NoProfile", "-C", "(Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -like \"*Ethernet*\" }).IPAddress")
		output, _ := cmd.CombinedOutput()
		return strings.TrimSpace(string(output))
	}
}

func getHostname() string {
	if runtime.GOOS == "linux" {
		cmd := exec.Command("hostname")
		output, _ := cmd.CombinedOutput()
		return strings.TrimSpace(string(output))
	} else {
		cmd := exec.Command("powershell.exe", "-NoProfile", "-C", "hostname")
		output, _ := cmd.CombinedOutput()
		return strings.TrimSpace(string(output))
	}
}

func getSudoGroupName() string {
	if runtime.GOOS != "linux" {
		return ""
	} else {
		group_file, _ := os.ReadFile("/etc/group")
		for _, group := range strings.Split(string(group_file), "\n") {
			tokens := strings.Split(string(group), ":")
			if tokens[0] == "sudo" || tokens[0] == "wheel" {
				return tokens[0]
			}
		}
		return ""
	}
}

func checkUserExists(username string, users string) bool {
	var userJson []localUserJson
	json.Unmarshal([]byte(users), &userJson)

	for _, user := range userJson {
		if user.User == username {
			return true
		}
	}
	return false
}

func getIsDC() bool {
	if runtime.GOOS != "windows" {
		return false
	} else {
		cmd := exec.Command("powershell.exe", "-NoProfile", "-C", "Get-WmiObject -Query 'select * from Win32_OperatingSystem where (ProductType = \"2\")'")
		output, _ := cmd.CombinedOutput()
		if len(output) != 0 {
			return true
		}
		return false
	}
}

func getToken() string {
	local_ip := getLocalIP()
	server_ip_address := getServerIPAddress()
	token := ""

	if runtime.GOOS == "windows" {
		tokenBytes, err := os.ReadFile("C:\\Program Files\\CCDC-Password-Manager\\token.txt")
		if err != nil {
			fmt.Println("Error reading token.txt:", err)
		}
		token = strings.TrimSpace(string(tokenBytes))
	} else {
		tokenBytes, err := os.ReadFile("/etc/ccdc-password-manager/token.txt")
		if err != nil {
			fmt.Println("Error reading token.txt:", err)
		}
		token = strings.TrimSpace(string(tokenBytes))
	}
	if token != "" {
		return token
	}

	hostname := getHostname()

	form := url.Values{}
	form.Add("ip_address", local_ip)
	form.Add("hostname", hostname)

	code := 400
	for code != 200 {
		resp, _ := http.PostForm("https://"+server_ip_address+"/register_client", form)
		defer resp.Body.Close()
		code = resp.StatusCode
		body, _ := io.ReadAll(resp.Body)
		token = string(body)
		if code != 200 {
			fmt.Println("Error registering client:", token)
			time.Sleep(30 * time.Second)
		}
	}
	
	if runtime.GOOS == "windows" {
		err := os.WriteFile("C:\\Program Files\\CCDC-Password-Manager\\token.txt", []byte(token), 0600)
		if err != nil {
			fmt.Println("Error writing token.txt:", err)
		}
	} else {
		err := os.WriteFile("/etc/ccdc-password-manager/token.txt", []byte(token), 0600)
		if err != nil {
			fmt.Println("Error writing token.txt:", err)
		}
	}

	return token
}

func getServerIPAddress() string {
	if runtime.GOOS == "windows" {
		serverIPBytes, err := os.ReadFile("C:\\Program Files\\CCDC-Password-Manager\\server_ip_address.txt")
		if err != nil {
			fmt.Println("Error Loading Server IP Address:", err)
		}
		server_ip := strings.TrimSpace(string(serverIPBytes))

		return server_ip
	} else {
		serverIPBytes, err := os.ReadFile("/etc/ccdc-password-manager/server_ip_address.txt")
		if err != nil {
			fmt.Println("Error Loading Server IP Address:", err)
		}
		server_ip := strings.TrimSpace(string(serverIPBytes))

		return server_ip
	}
}

func changeUserPassword(username string, newPassword string, is_dc bool) error {
	if newPassword == "None" {
		return nil
	}

	if runtime.GOOS == "linux" {
		cmd := exec.Command(Chpasswd_path)
		input := fmt.Sprintf("%s:%s", username, newPassword)
		cmd.Stdin = strings.NewReader(input)
		_, err := cmd.CombinedOutput()
		return err
	} else {
		if is_dc {
			cmd := exec.Command("powershell.exe", "-NoProfile", "-C", "Set-ADAccountPassword -Identity \""+username+"\" -Reset -NewPassword (ConvertTo-SecureString \""+newPassword+"\" -AsPlainText -Force)")
			_, err := cmd.CombinedOutput()
			return err
		} else {
			cmd := exec.Command("powershell.exe", "-NoProfile", "-C", "Set-LocalUser -Name \""+username+"\" -Password (ConvertTo-SecureString \""+newPassword+"\" -AsPlainText -Force)")
			_, err := cmd.CombinedOutput()
			return err
		}
	}
}

func changeAdminStatus(username string, isAdmin bool, is_dc bool, sudo_group_name string) error {
	if runtime.GOOS != "windows" {
		if isAdmin {
			cmd := exec.Command(Usermod_path, "-aG", sudo_group_name, username)
			_, err := cmd.CombinedOutput()
			return err
		} else {
			cmd := exec.Command(Gpasswd_path, "-d", username, sudo_group_name)
			_, err := cmd.CombinedOutput()
			return err
		}
	} else {
		command_to_run := ""
		if is_dc {
			command_to_run = "Get-ADGroupMember -Identity \"Domain Admins\" | Select-Object name | format-table -hideTableHeaders"
		} else {
			command_to_run = "Get-LocalGroupMember Administrators | select-object name | format-table -hideTableHeaders"
		}
		cmd := exec.Command("powershell.exe", "-NoProfile", "-C", command_to_run)
		output, _ := cmd.CombinedOutput()
		admin_users_list := strings.Split(string(output), "\r\n")
		already_admin := false
		for _, admin_user := range admin_users_list {
			admin_user = strings.TrimSpace(admin_user)
			if strings.Contains(admin_user, username) {
				already_admin = true
				break
			}
		}
		if already_admin && isAdmin {
			return nil
		}
		if !already_admin && !isAdmin {
			return nil
		}

		command_to_run = ""
		if isAdmin {
			if is_dc {
				command_to_run = "Add-ADGroupMember -Identity \"Domain Admins\" -Members \"" + username + "\""
			} else {
				command_to_run = "Add-LocalGroupMember -Group Administrators -Member \"" + username + "\""
			}
		} else {
			if is_dc {
				command_to_run = "Remove-ADGroupMember -Identity \"Domain Admins\" -Members \"" + username + "\" -Confirm:$false"
			} else {
				command_to_run = "Remove-LocalGroupMember -Group Administrators -Member \"" + username + "\""
			}
		}

		cmd = exec.Command("powershell.exe", "-NoProfile", "-C", command_to_run)
		_, err := cmd.CombinedOutput()
		return err
	}
}

func changeUserEnabledStatus(username string, isEnabled bool, is_dc bool) error {
	if runtime.GOOS != "windows" {
		shell := "/bin/bash"
        if !isEnabled {
            shell = "/usr/sbin/nologin"
        }

        cmd := exec.Command(Usermod_path, "-s", shell, username)
        
        _, err := cmd.CombinedOutput()
        return err
	} else {
		cmd_to_run := ""
		if is_dc {
			cmd_to_run = "Get-ADUser -Identity \"" + username + "\" | Select-Object Enabled | format-table -hideTableHeaders"
		} else {
			cmd_to_run = "get-localuser | select-object name, enabled | format-table -hideTableHeaders"
		}
		cmd := exec.Command("powershell.exe", "-NoProfile", "-C", cmd_to_run)
		output, _ := cmd.CombinedOutput()
		users := strings.Split(string(output), "\r\n")
		currently_enabled := false
		for _, user := range users {
			if strings.Contains(user, username) {
				tokens := strings.Fields(user)
				enabled := tokens[1]
				enabled = strings.TrimSpace(enabled)
				enabled = strings.ToLower(enabled)
				if enabled == "true" {
					currently_enabled = true
				} else {
					currently_enabled = false
				}
				break
			}
		}
		if currently_enabled == isEnabled {
			return nil
		}

		if isEnabled {
			cmd := exec.Command("powershell.exe", "-NoProfile", "-C", "Enable-LocalUser -Name \""+username+"\"")
			_, err := cmd.CombinedOutput()
			return err
		} else {
			cmd := exec.Command("powershell.exe", "-NoProfile", "-C", "Disable-LocalUser -Name \""+username+"\"")
			_, err := cmd.CombinedOutput()
			return err
		}
	}
}

func createUser(username string, password string, isEnabled bool, isAdmin bool, is_dc bool, sudo_group_name string) error {
	if runtime.GOOS != "windows" {
		cmd := exec.Command(Useradd_path, "-m", username)
		_, err := cmd.CombinedOutput()
		if err != nil {
			return err
		}
		setUserPasswordErr := changeUserPassword(username, password, is_dc)
		if setUserPasswordErr != nil {
			return setUserPasswordErr
		}
		changeAdminErr := changeAdminStatus(username, isAdmin, is_dc, sudo_group_name)
		if changeAdminErr != nil {
			return changeAdminErr
		}
		changeEnabledErr := changeUserEnabledStatus(username, isEnabled, is_dc)
		if changeEnabledErr != nil {
			return changeEnabledErr
		}
		return nil
	} else {
		cmd := exec.Command("powershell.exe", "-NoProfile", "-C", "New-LocalUser -Name \""+username+"\" -Password (ConvertTo-SecureString \""+password+"\" -AsPlainText -Force)")
		_, err := cmd.CombinedOutput()
		if err != nil {
			return err
		}
		changeAdminErr := changeAdminStatus(username, isAdmin, is_dc, sudo_group_name)
		if changeAdminErr != nil {
			return changeAdminErr
		}
		changeEnabledErr := changeUserEnabledStatus(username, isEnabled, is_dc)
		if changeEnabledErr != nil {
			return changeEnabledErr
		}
		return nil
	}
}

func must(v string, err error) string {
    if err != nil {
        log.Fatalf("fatal error: %v", err)
    }
    return v
}

func mainLoop() {
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	is_dc := getIsDC()
	local_ip := getLocalIP()
	setLocalBinaries()

	sudo_group_name := getSudoGroupName()
	server_ip_address := getServerIPAddress()
	token := getToken()
	local_users := getLocalUsers(is_dc)

	i := 0

	form := url.Values{}
	form.Add("ip_address", local_ip)
	form.Add("local_users", local_users)
	form.Add("authoriztion_token", token)

	resp, _ := http.PostForm("https://"+server_ip_address+"/update_local_users", form)

	for {
		i += 1
		if i%5 == 0 {
			new_local_user_list := getLocalUsers(is_dc)
			if !reflect.DeepEqual(new_local_user_list, local_users) {

				local_users = new_local_user_list

				form = url.Values{}
				form.Add("ip_address", local_ip)
				form.Add("local_users", new_local_user_list)
				form.Add("authoriztion_token", token)

				resp, _ = http.PostForm("https://"+server_ip_address+"/update_local_users", form)
			}
		}

		form = url.Values{}
		form.Add("ip_address", local_ip)
		form.Add("authoriztion_token", token)

		resp, _ = http.PostForm("https://"+server_ip_address+"/get_passwords_to_claim", form)
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)

		if len(body) != 0 {
			var userPasswords passwordJson
			json.Unmarshal(body, &userPasswords)

			var userPasswordChangeStatus []UserPasswordChangeStatus

			for _, userToChangePassword := range userPasswords.Users {

				if checkUserExists(userToChangePassword.Username, local_users) {
					setUserPasswordErr := changeUserPassword(userToChangePassword.Username, userToChangePassword.Password, is_dc)
					if setUserPasswordErr != nil {
						userPasswordChangeStatus = append(userPasswordChangeStatus, UserPasswordChangeStatus{Status: setUserPasswordErr.Error(), Username: userToChangePassword.Username})
					} else {
						userPasswordChangeStatus = append(userPasswordChangeStatus, UserPasswordChangeStatus{Status: "Success", Username: userToChangePassword.Username})
					}

					changeAdminErr := changeAdminStatus(userToChangePassword.Username, userToChangePassword.Admin, is_dc, sudo_group_name)
					if changeAdminErr != nil {
						userPasswordChangeStatus = append(userPasswordChangeStatus, UserPasswordChangeStatus{Status: changeAdminErr.Error(), Username: userToChangePassword.Username})
					} else {
						userPasswordChangeStatus = append(userPasswordChangeStatus, UserPasswordChangeStatus{Status: "Success", Username: userToChangePassword.Username})
					}

					changeEnabledErr := changeUserEnabledStatus(userToChangePassword.Username, userToChangePassword.Enabled, is_dc)
					if changeEnabledErr != nil {
						userPasswordChangeStatus = append(userPasswordChangeStatus, UserPasswordChangeStatus{Status: changeEnabledErr.Error(), Username: userToChangePassword.Username})
					} else {
						userPasswordChangeStatus = append(userPasswordChangeStatus, UserPasswordChangeStatus{Status: "Success", Username: userToChangePassword.Username})
					}
				} else {
					userCreatedErr := createUser(userToChangePassword.Username, userToChangePassword.Password, userToChangePassword.Enabled, userToChangePassword.Admin, is_dc, sudo_group_name)
					if userCreatedErr != nil {
						userPasswordChangeStatus = append(userPasswordChangeStatus, UserPasswordChangeStatus{Status: userCreatedErr.Error(), Username: userToChangePassword.Username})
					} else {
						userPasswordChangeStatus = append(userPasswordChangeStatus, UserPasswordChangeStatus{Status: "Success", Username: userToChangePassword.Username})
					}
				}
			}

			fmt.Println("User Password Change Statuses:", userPasswordChangeStatus)

			if len(userPasswordChangeStatus) != 0 {
				jsonBytes, _ := json.Marshal(userPasswordChangeStatus)
				form = url.Values{}
				form.Add("ip_address", local_ip)
				form.Add("user_status", string(jsonBytes))
				form.Add("authoriztion_token", token)

				resp, _ = http.PostForm("https://"+server_ip_address+"/update_password_change_status", form)
			}
		}

		time.Sleep(15 * time.Second)
	}
}