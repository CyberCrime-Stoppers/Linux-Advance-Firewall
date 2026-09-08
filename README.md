# Linux-Advance-Firewall
Advanced Linux Firewall - For I.Ts - whether that is for business/small business or Home Users, just want more with their firewall &amp; security..

support me giving me ideas. give-me-ideas@mailservices2.simplelogin.com

## its not quite finished yet, there are no proper interface yet localhost/::8080
### also building permissions in order for users to get proper admin controls on their machine locally and/or having an option through a web-browser as default.


Huge things coming for linux and the firewalls will be more customizable and more control over who has access online and 
network security signed to specific groups/users of your chosen. great tool for business and small-businesses and home/home-lab users 


Goal: Build a native app and a proper web UI, with options for users to create their own login screen and hosted their personal servers not limited too, usernames and passwordless system and second-factor authentication. Everything runs locally through a user-controlled intranet — no phoning home, no direct company oversight on how it's set up or used. Not even the World Wide Web can log in or access another user's login UI through the Internet. Plain old Intranet.


Ubuntu/Debian:

sudo apt-get install gcc libsqlite3-dev


System-Level Dependencies (Install on Your Machine)
These are programs you need installed before the project will work:

#Dependency				                           	#Purpose							                                 #Install Command (Ubuntu/Debian)
-<span>Go (1.21+)</span>			            	  -Compiles and runs the server	  	    	              -sudo apt install golang-go (you already have this via snap)-	
-gcc / build-essential		                    -Compiles the SQLite C bindings		                    -sudo apt install build-essential	
-libsqlite3-dev			                          -SQLite development headers				                    -sudo apt install libsqlite3-dev	
-nftables (kernel-side)		                    -The actual firewall — Linux kernel ≥ 3.13	          -Already built into modern kernels	
-root / CAP_NET_ADMIN		                      -Permission to talk to the kernel firewall	          -sudo when running the server	
-Node.js + npm (frontend only)	              -Runs the React dev server				                    -sudo apt install nodejs npm	
