# bashthing_rpc
bashthing_rpc - simple script to find print services for PrintNightmare

7/1/2021

This script is basically a prototype scanner for Windows Print Service. You could tweak it to do other things if you need. I use a more refined version to do Bluekeep/WannaCry/etc.

I thought I would share this, it might be helpful to someone in a crunch, at least while the vulnerability remains patchless.

================================================================================
[0] - LIST ALL DOMAIN CONTROLLERS
[1] - CHECK FOR PRINT SERVICE [ALL DOMAIN CONTROLLERS]
[2] - CHECK SINGLE HOST FOR PRINT SERVICE
[3] - CHECK LIST FOR PRINT SERVICE
[4] - PERFORM MASSCAN/CHECK RESULT FOR PRINT SERVICE
================================================================================

This should be simple and self-explanatory.

Dependencies:

bash, dig, masscan, python/impacket (this uses rpcdump.py in examples, but other methods exist too)
