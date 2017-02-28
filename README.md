# DashButton
Catch packets from Amazon dash buttons and call a url

Add the mac addresses of your buttons to the ini, then a tab, then the url you want to call when it pops on the network.

There are a couple packets they send out. I just picked the mac/port 67 combination to respond to. The 1 second delay is there because you see the same packet twice from some buttons.
