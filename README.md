# DPB_Group_Policy
Here we have a few little scripts designed to help with group policy. This is my first public script, please let me know if I need to fix things. 

<h3>Modules Needed</h3>
You will need the active directory and the grouppolicy modules. 

<h2>Get-ComputerPCGPO</h2>
Grabs the group policy form target computer for either the computer itself or for the user name provided, assuming the username is on the computer. 

<h2>Get-GPOName</h2>
Often times I can't remember all the names of group policy but I will remember parts of the name. In this script I can quickly search for group policy names.

<h2>Search-UsersOnComputerForGPO</h2>
This little bad boy will search all the users in a single computer for a group policy that you tell it. The best part is it combines the Get-UsersGPO and Get-GroupPolicyName. This way if you can't remember the full name, your good to go. 

Like I said before, this is my first time creating a module. I have been making scripts for years, but never a module. I thought I would share it. I hope you all like it. 
