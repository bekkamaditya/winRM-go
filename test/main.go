package main

import (
    "winrm"
    "os"
	"fmt"
)

func main(){
	endpoint := winrm.NewEndpoint("10.7.84.229", 5985, false, false, nil, nil, nil, 0)
	params := winrm.DefaultParameters
	params.TransportDecorator = func() winrm.Transporter { return &winrm.ClientNTLM{} }
	client, err := winrm.NewClientWithParameters(endpoint, "administrator","", "nutanix/4u",params)
	if err != nil {
		fmt.Println(err)
		panic(err)
	}
	fmt.Println("%+v\n",*client)
	client.Run("ipconfig /all", os.Stdout, os.Stderr)
}
