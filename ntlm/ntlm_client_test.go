package ntlm

import (
	"fmt"
	"testing"
)

func TestClientWithDomain(t *testing.T) {
	c := NewClient("administrator", "QA", "Nutanix/4u", "10.7.55.76", 5985)
	fmt.Println(c.SendMessage(nil))
}

func TestClientWithoutDomain(t *testing.T) {
	c := NewClient("administrator", "", "Nutanix/4u", "10.7.55.76", 5985)
	fmt.Println(c.SendMessage(nil))
}

func TestClientNegWithDomain(t *testing.T) {
	c := NewClient("administrator", "QA", "Nutanix4u", "10.7.55.76", 5985)
	fmt.Println(c.SendMessage(nil))
}

func TestClientNegWithoutDomain(t *testing.T) {
	c := NewClient("administrator", "", "Nutanix4u", "10.7.55.76", 5985)
	fmt.Println(c.SendMessage(nil))
}
