#!/bin/bash

. $(dirname ${BASH_SOURCE})/../util.sh

desc_type "Kubernetes 1.25 will support user namespaces (KEP 127)"
desc_type "This video shows:"
desc_type "	* A small introduction to user namespaces"
desc_type "	* An exploit of CVE-2022-0492: Can containers escape?"
desc_type "	* How user namespaces block this (and more) exploits"
desc_type ""
desc_type "Containers in k8s today use a network namespace, PID namespace, mount namespace, etc."
desc_type "However, they are not using a user namespace"
desc_type ""
desc_type "A user namespace allows us to map a user in the container to a different user on the host"
desc_type "For example:"
desc ""
desc "          Container UID       Host UID"
desc "            0 (root)           10000 (unprivileged) "
desc ""
desc_type "In this example, the UID 0 (root) in the container is mapped to UID 10000 on the host"
desc_type "If they escape the container, they don't have root privileges on the host"
desc_type "They are running as UID 10000 in the host"
desc_type "Their root permissions are limited to the user namespace"
desc_type "Their capabilities too (only valid in the user namespace)"
desc_type "There are some more things that change, for more details see:"
desc      "		man 7 user_namespaces"
desc ""
desc_type "Furthermore, user namespaces increase the isolation and could have avoided several CVEs already"
desc_type "Like:"
desc "		CVE-2019-5736:  Host runc binary can be overwritten from container. Completely mitigated with userns"
desc "			        Score: 8.6 (HIGH)"
desc "		CVE-2021-25741: Mitigated as root in the container is not root in the host"
desc "				Score: 8.1 (HIGH) / 8.8 (HIGH)"
desc "		... and several more"
desc ""

desc_type ""
desc_type "In fact, while we are working on this KEP, some more CVEs that userns protects against were found"
desc_type "Let's see an example of a recent CVE:"
desc ""
desc "				CVE-2022-0492: Can containers escape?"
desc "					       Score: 7.8"
desc "					       March 3, 2022"
desc ""
desc_type "We created an exploit of this CVE for Kubernetes"

desc_type "Let's see how this exploit works in vanilla k8s 1.24"
desc_type "Then, let's see what happens if we try to run the exploit when the pod uses user namespaces"
desc_type ""
run "kubectl get nodes"

function krun {
	run "kubectl exec -ti $krun_pod -- bash -c \"$1\""
}

function kwait {
	# We can't run kubecte get pods -w, as that doesn't stop when it is running.
	# Let's just do this loop, that stops when it is running.
	while true; do
	    run "kubectl get pod $krun_pod"
	    # It will be nice to use the output of that command, but
            # DEMO_RUN_STDOUT spacing is kind of broken
            # So, lets run it again...
	    status=$(kubectl get pod $krun_pod | tail -1 | awk '{print $3}')
	    if [ "$status" == "Running" ]; then
	        break
	    fi
	done
}

function host_ps {
	run "ps faux | grep \"$1\" | grep -v grep"
}

function cve_check {
	desc_type "Let's see if the file was created"
	run "ls -l /cve-2022-0492"
	desc_type "Let's see the content of the file"
	run "cat /cve-2022-0492"
	desc_type "Is the sleep 123456 process running?"
	host_ps "sleep 123456"
}

krun_pod="cve-pod-host-users"

desc_type "Let's create a pod without user namespaces"
run "cat $(relative cve-pod-host-users.yaml)"
run "kubectl apply -f $(relative cve-pod-host-users.yaml)"
kwait
desc_type "Let's see from the host as which user it is running"
host_ps "sleep infinity"
desc_type "It is running as root on the host"

run "cat $(relative cve-script)"
desc_type "Look at the CVE script and the comments"
run "sleep 20"
desc_type "Let's upload the script to exploit the cve"
run "kubectl cp $(relative cve-script) $krun_pod:/"
desc_type "If the script runs successfully, it will create a file in / on the HOST"
krun "chmod +x /cve-script; ./cve-script"
cve_check
desc_type "Indeed it executes as root and created the file on /!"
# scared emoji
desc_type "\U1F631"
#echo -e "\U1F631"
#prompt

run "kubectl delete pod $krun_pod"
desc "Also, I'm running in the background:"
desc "sudo rm /cve-2022-0492"
sudo rm -f /cve-2022-0492
desc "sudo pkill -f \"sleep 12345\""
sudo pkill -f "sleep 12345"
desc ""

krun_pod="cve-pod-userns"

desc_type "Let's create a pod with user namespaces enabled now"
desc_type "It is the same pod, but with the hostUsers=false field"
desc_type "This enables user namespaces"
run "cat $(relative cve-pod-userns.yaml)"
run "kubectl apply -f $(relative cve-pod-userns.yaml)"

# Wait for the pod to be running.
kwait

desc_type "With user namespaces, we map root in the container to a different (unprivileged) user on the host"
desc_type "Let's see from the host as which user it is running"
host_ps "sleep infinity"
desc_type "As this is not root on the host, it should not be able to write the release_agent file"

desc_type "Let's upload the script to exploit the CVE"
run "cat $(relative cve-script)"
run "kubectl cp $(relative cve-script) $krun_pod:/"
desc_type "Again, if the script runs successfully, it will create a file in /"

desc_type "But mount, the first line of the script, will fail"
krun "mount -t cgroup -o rdma cgroup /mnt/"

desc_type "Let's then, run the script inside a nested userns where we can mount"
desc_type "Let's see if the exploit works..."

# Crossed fingers emoji
desc_type "\U1F91E"
#echo -e "\U1F91E"
#prompt

krun "unshare -UrmC bash -x /cve-script"
desc_type "Take a few seconds to see that, while the mount works now, the exploit still seems to fail"
run "sleep 15"
desc_type "So, what happened?"
desc_type "As we said, now the mount works. But the exploit is not able to write the release_agent"
desc_type "This is, we couldn't register our script to be later executed as root"
desc_type "We couldn't write the notify_on_release and cgroups.procs files either"
desc_type "So, it seems the exploit didn't work. But let's check to be sure"
cve_check
# emoji party
desc_type "\U1F389"

run "kubectl delete pod $krun_pod"
desc_type "The exploit doesn't work because the container doesn't run as root on the HOST"
desc_type "The files can only be written by root on the HOST"
desc_type "However, the container still thinks it is running as root"
desc_type "User namespaces gives this powerful abstraction of users"
desc_type "Lot of images that run as root will:"
desc_type "  * continue to run fine and unmodified if user namespaces are enabled"
desc_type "  * be protected, as they don't really run as root"
desc ""
desc_type "Coming soon, to a k8s cluster near you :)"

