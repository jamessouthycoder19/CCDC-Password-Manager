//go:build windows

package main

import (
    "github.com/kardianos/service"
)

type program struct{}

func (p *program) Start(s service.Service) error {
	go p.run()
	return nil
}

func (p *program) run() {
	mainLoop()
}

func (p *program) Stop(s service.Service) error {
	return nil
}

func runAsService() {
	svcConfig := &service.Config{
		Name:        "CCDC Password Manager",
		DisplayName: "CCDC Password Manager",
		Description: "CCDC Password Manager Client Service",
	}

	prg := &program{}
	s, _ := service.New(prg, svcConfig)
	s.Run()
}