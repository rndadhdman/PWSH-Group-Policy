# DPB_Group_Policy
Here we have a few little scripts designed to help with group policy. This is my first public script, please let me know if I need to fix things. 

<h3>Modules Needed</h3>
You will need the active directory and the grouppolicy modules. 

<h2>Get-UsersGPO</h2>
This script will grab the group policy that has been applied to a user on a target machine. You can choose mutliple users and computers as well. So, if you want to know each policy applied to bob from marketing while he was on all of the marketing computers and compare it to fob, this is how you would do that. <b>Get-UsersGPO -Usernames Bob,Fob -ComputerNames Marketing1,Marketing2,Marketing3,Marketing4,Marketing5</b>

If the computer is powered off the script will present an warning that the computer is off. If the script can run on the computer for whatever reason, then the script will state the data was not collected. 

You also may use the Credentials tag. It is a object and requires as such. 

<h2>Get-PCGPO</h2>
This script grabs the applied group policy information to the computer in question. For example <b>Get-PCGPO -ComputerNames <server1>,<server2></b> will give you the group policy information from both servers. 

Once again, if the comptuer is powered off, then you will be greeted with a warning.

<h2>Get-GroupPolicyName</h2>
Often times I can't remember all the names of group policy but I will remember parts of the name. In this script I can quickly search for group policy names.

<h2>Search-UsersOnComputerForGPO</h2>
This little bad boy will search all the users in a single computer for a group policy that you tell it. The best part is it combines the Get-UsersGPO and Get-GroupPolicyName. This way if you can't remember the full name, your good to go. 

Like I said before, this is my first time creating a module. I have been making scripts for years, but never a module. I thought I would share it. I hope you all like it. 
