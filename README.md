# Compiling the assignment

To compile the assignment use "make" or "make build"

An executable file  named "antivirus" should be created

# Running the assignment

You can run all of the functions together by using "make run"

or

You can run a single function by using "make <function_name>"
eg: make slice, make inspect ...

The previous 2 methods will run a predetermined test for each function

You can mannualy run the functions with other parameters as such:

./antivirus scan/inspect/monitor <dir_name>
./antivirus slice <secret_key>
./antivirus unlock <pair1> <pair2> <pair3> ...

# What is working and what is not working

I think that everything is working just fine except for
a couple concerns that I've got.

I am concerned about the "inspect" function because I think
that it does not collect all of the urls present in the files.
That is happening, I think, because of the regular expression
which is used to determine if a string is a url or not.

Also I didn't fully understand what I was asked to do for
the "unlock" function when it is provided with more than 3
pairs and so I just use the first 3 provided pairs.

# Bonus: Yara rule and arya command

This is tha yara rule I used to describe the KozaliBear attack:

import "hash"

rule KozaliBear{

    strings:
        $bitcoin = "bc1qa5wkgaew2dkv56kfvj49j0av5nml45x9ek9hz6"
        $signature = {98 1d 00 00 ec 33 ff ff fb 06 00 00 00 46 0e 10}

    condition:
        $bitcoin or $signature or 
        hash.md5(0, filesize) == "85578cd4404c6d586cd0ae1b36c98aca" or 
        hash.sha256(0, filesize) == "d56d67f2c43411d966525b3250bfaa1a85db34bf371468df1b6a9882fee78849"

}

This is the arya command I used:

python3 <path>/arya.py -i <yara_rules> -o <output_filename>

<path> is the path where arya is installed in your system

<yara_rules> is the file where the above yara rules are saved

<output_filename> is the name of the malware file to be created
