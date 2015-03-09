#!/usr/bin/python
#
# Simple script that looks for INDX records at 4096 (decimal) byte boundaries on a raw disk. 
# It saves the INDX records to a binary output file that can be parsed with INDXparse.py. 
#	Tested against Windows Server 2003
#
#   Copyright 2015, Jacob Garner <jacob.garner@mandiant.com> 
#                    while at Mandiant <http://www.mandiant.com>
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

import sys
if sys.argv[1] == "-h":
	print "\tpython ./INDXfind.py <ewfmount'd drive>"
	print "\tex:\tpython ./INDXfind.py /mnt/ewf/ewf1"
	sys.exit()

f = open(sys.argv[1], 'rb')			# ewfmount'd drive expected as first argument on command line
indxBytes = "494e445828000900"  		# 49 4e 44 58 28 00 09 00  "INDX( header"
offset = 0 					# data processed
byteChunk="go" 					# cheap do-while
recordsFound = 0 				# for progress
outFile = open("INDX_records.raw", 'wb')	# output file

print	"\n\tRunning... progress will output every GigaByte. In testing this was every 15-20 seconds.\n" \
	"\tThe output file is named \"INDX_records.raw\".\n" \
	"\tINDX_records.raw should be parsed with INDXparser.py which can be found at:\thttps://github.com/williballenthin/INDXParse\n" 

while byteChunk != "":
	byteChunk = f.read(4096)	# Only searching for cluster aligned (4096 on Windows Server 2003) INDX records... records all appear to be 4096 bytes
	compare = byteChunk[0:8]	# Compare INDX header to first 8 bytes of the byteChunk
	if compare.encode("hex") == indxBytes:
		recordsFound = recordsFound + 1
		outFile.write(byteChunk) # Write the byteChunk to the output file

	offset = offset + 4096		# Update offset for progress tracking

	# Progress
	if offset % 1073741824 == 0:
		print "Processed: %d GB. INDX records found: %d" % ((offset / 1073741824), recordsFound)

outFile.close()
