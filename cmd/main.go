package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/abakum/knownhosts"
	"github.com/abakum/pageant"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var (
	host22  = "10.161.115.189:22"
	host222 = "10.161.115.189:222"
	khPath  = ""
	user    = "user_"
)

func main() {
	log.SetFlags(log.Lshortfile)

	hd, err := os.UserHomeDir()
	if err != nil {
		log.Println("error on UserHomeDir:", err)
		return
	}
	khPath = filepath.Join(hd, ".ssh", "known_hosts")

	conn, err := pageant.NewConn()
	if err != nil {
		log.Println("error on NewConn:", err)
		return
	}
	defer conn.Close()
	sshAgent := agent.NewClient(conn)

	keys, err := sshAgent.List()
	if err != nil {
		log.Println("error on agent.List:", err)
		return
	}
	if len(keys) == 0 {
		log.Println("no keys listed by Pagent")
		return
	}

	for _, host := range []string{host22, host222} {
		// ExampleNew(sshAgent, host)
		// NewWriteKnownHost(sshAgent, host)
		ExampleNewDB(sshAgent, host)
		NewDBWriteKnownHost(sshAgent, host)
	}
}

func ExampleNew(sshAgent agent.ExtendedAgent, host string) {
	kh, err := knownhosts.New(khPath)
	if err != nil {
		log.Println("Failed to read known_hosts: ", err)
		return
	}
	config := &ssh.ClientConfig{
		Timeout:           time.Second,
		User:              user,
		Auth:              []ssh.AuthMethod{ssh.PublicKeysCallback(sshAgent.Signers)},
		HostKeyCallback:   kh.HostKeyCallback(),
		HostKeyAlgorithms: kh.HostKeyAlgorithms(host),
	}
	log.Printf("%v\n", config.HostKeyAlgorithms)
	client, err := ssh.Dial("tcp", host, config)
	if err != nil {
		log.Println("Failed to dial: ", err)
		return
	}
	defer client.Close()
}

func ExampleNewDB(sshAgent agent.ExtendedAgent, host string) {
	kh, err := knownhosts.NewDB(khPath)
	if err != nil {
		log.Println("Failed to read known_hosts: ", err)
		return
	}
	config := &ssh.ClientConfig{
		Timeout:           time.Second,
		User:              user,
		Auth:              []ssh.AuthMethod{ssh.PublicKeysCallback(sshAgent.Signers)},
		HostKeyCallback:   kh.HostKeyCallback(),
		HostKeyAlgorithms: kh.HostKeyAlgorithms(host),
	}
	log.Printf("%v\n", config.HostKeyAlgorithms)
	client, err := ssh.Dial("tcp", host, config)
	if err != nil {
		log.Println("Failed to dial: ", err)
		return
	}
	defer client.Close()
}

func NewDBWriteKnownHost(sshAgent agent.ExtendedAgent, host string) {
	kh, err := knownhosts.NewDB(khPath)
	if err != nil {

		log.Println("Failed to read known_hosts: ", err)
		return
	}

	// Create a custom permissive hostkey callback which still errors on hosts
	// with changed keys, but allows unknown hosts and adds them to known_hosts
	cb := ssh.HostKeyCallback(func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		innerCallback := kh.HostKeyCallback()
		err := innerCallback(hostname, remote, key)
		log.Println("innerCallback(hostname, remote, key)", err)
		log.Println("knownhosts.IsHostKeyChanged(err)", knownhosts.IsHostKeyChanged(err))
		log.Println("knownhosts.IsHostUnknown(err)", knownhosts.IsHostUnknown(err))
		if knownhosts.IsHostKeyChanged(err) {
			return fmt.Errorf("REMOTE HOST IDENTIFICATION HAS CHANGED for host %s! This may indicate a MitM attack.", hostname)
		} else if knownhosts.IsHostUnknown(err) {
			f, ferr := os.OpenFile(khPath, os.O_APPEND|os.O_WRONLY, 0600)
			if ferr == nil {
				defer f.Close()
				ferr = knownhosts.WriteKnownHost(f, hostname, remote, key)
			}
			if ferr == nil {
				log.Printf("Added host %s to known_hosts\n", hostname)
			} else {
				log.Printf("Failed to add host %s to known_hosts: %v\n", hostname, ferr)
			}
			return nil // permit previously-unknown hosts (warning: may be insecure)
		}
		return err
	})

	config := &ssh.ClientConfig{
		Timeout:           time.Second,
		User:              user,
		Auth:              []ssh.AuthMethod{ssh.PublicKeysCallback(sshAgent.Signers)},
		HostKeyCallback:   cb,
		HostKeyAlgorithms: kh.HostKeyAlgorithms(host),
	}
	log.Printf("%v\n", config.HostKeyAlgorithms)
	client, err := ssh.Dial("tcp", host, config)
	if err != nil {
		log.Println("Failed to dial: ", err)
		return
	}
	defer client.Close()
}

func NewWriteKnownHost(sshAgent agent.ExtendedAgent, host string) {
	kh, err := knownhosts.New(khPath)
	if err != nil {

		log.Println("Failed to read known_hosts: ", err)
		return
	}

	// Create a custom permissive hostkey callback which still errors on hosts
	// with changed keys, but allows unknown hosts and adds them to known_hosts
	cb := ssh.HostKeyCallback(func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		err := kh(hostname, remote, key)
		log.Println("kh(hostname, remote, key)", err)
		log.Println("knownhosts.IsHostKeyChanged(err)", knownhosts.IsHostKeyChanged(err))
		log.Println("knownhosts.IsHostUnknown(err)", knownhosts.IsHostUnknown(err))
		if knownhosts.IsHostKeyChanged(err) {
			return fmt.Errorf("REMOTE HOST IDENTIFICATION HAS CHANGED for host %s! This may indicate a MitM attack.", hostname)
		} else if knownhosts.IsHostUnknown(err) {
			f, ferr := os.OpenFile(khPath, os.O_APPEND|os.O_WRONLY, 0600)
			if ferr == nil {
				defer f.Close()
				ferr = knownhosts.WriteKnownHost(f, hostname, remote, key)
			}
			if ferr == nil {
				log.Printf("Added host %s to known_hosts\n", hostname)
			} else {
				log.Printf("Failed to add host %s to known_hosts: %v\n", hostname, ferr)
			}
			return nil // permit previously-unknown hosts (warning: may be insecure)
		}
		return err
	})

	config := &ssh.ClientConfig{
		Timeout:           time.Second,
		User:              user,
		Auth:              []ssh.AuthMethod{ssh.PublicKeysCallback(sshAgent.Signers)},
		HostKeyCallback:   cb,
		HostKeyAlgorithms: kh.HostKeyAlgorithms(host),
	}
	log.Printf("%v\n", config.HostKeyAlgorithms)
	client, err := ssh.Dial("tcp", host, config)
	if err != nil {
		log.Println("Failed to dial: ", err)
		return
	}
	defer client.Close()
}
