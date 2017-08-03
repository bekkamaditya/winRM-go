package main

import(
	"fmt"
	"winrm/ntlm"
)

func mains(){
	ncli := ntlm.NewClient("administrator","","nutanix/4u","10.7.84.229",5985)
	fmt.Println("Authentication started")
	ncli.Authenticate()
	fmt.Println("Authentication done")
}
