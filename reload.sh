#!/bin/sh

MODULE="cryptor"

print_message () {
	if [ $(tput colors) -ge 8 ]; then
 		RED=$(tput setaf 1)
 		RESET=$(tput sgr0)
		echo "${RED}[+] - ${1} ${RESET}"
	else
		echo "${1}"
	fi
}
if lsmod | grep -wq "$MODULE"; then
	print_message "Unloading kernel module !"
	rmmod $MODULE
else
	print_message "UNLOADED!"

fi

print_message "Compiling ..."
make

print_message "Inserting module ..."
insmod $MODULE.ko

print_message "Fine !"
