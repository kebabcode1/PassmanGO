## Description

Zero-knowledge, offline password manager, focused on security that is GO based. Runs in CLI with secure encryption protocols ssuch as AES-GCM for safe password storage.

## Installation

Install yay ( if you have not )
  
  sudo pacman -S --needed git base-devel
  
  git clone https://aur.archlinux.org/yay.git
  
  cd yay
  
  makepkg -si

## Install PassmanGO /Arch Linux
  
  yay -S passmango-bin

## Manual installation /Windows /Mac /Linux
Clone the repo: git clone https://github.com/kebabcode1/PassmanGO.git 

Install dependencies: go mod tidy 

Build: go build -o PassmanGO

## Post-installation/How to use

To use it, simply type " passmango " in the console.
