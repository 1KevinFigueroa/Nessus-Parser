#########################################################################################
#   Author: Kevin Figueroa
#   
#   Purpose: Import, convert, and parse Nessus CSV results into Excel 
#            spreadsheet for easily readable format to quickly evaluate 
#            vulnerability
#
#   Name: nessusParser_v0.3.py
#
#   Copyright (c) 2017, Kevin Figueroa
#   All rights reserved.
#
#   Redistribution and use in source and binary forms, with or without
#   modification, are permitted provided that the following conditions are met:
#
#   1. Redistributions of source code must retain the above copyright notice, this
#      list of conditions and the following disclaimer.
#   2. Redistributions in binary form must reproduce the above copyright notice,
#      this list of conditions and the following disclaimer in the documentation
#      and/or other materials provided with the distribution.
#
#   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
#   ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
#   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
#   DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
#   ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
#   (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
#   LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
#   ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
#   SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#   The views and conclusions contained in the software and documentation are those
#   of the authors and should not be interpreted as representing official policies,
#   either expressed or implied, of the FreeBSD Project.
#########################################################################################

#!/usr/bin/env python

import os, sys
import csv
import argparse
import xlsxwriter
from xlsxwriter.workbook import Workbook


parser = argparse.ArgumentParser(description='USAGE: nessusParser_v0.3.py <filename.csv>')
parser.add_argument("INCLUDE NESSUS CSV FILE IN COMMAND-LINE!")
args = parser.parse_args()



if (sys.argv == 1):
	parser.print_help(args[2])
	sys.exit(1)

import_nessusCSV = sys.argv[1]
open_NessusCSV = open(sys.argv[1], 'rb')
read_NessusCSV = csv.reader(open_NessusCSV)



# Generator new CSV FILE for manipulation and parsing extraction
tg = open('templateGenerator.csv', 'wb')
tgWriter = csv.writer(tg)

for row in read_NessusCSV:
	tgWriter.writerow(row)
tg.close()



nessusCSV_xlsx = import_nessusCSV.replace('.csv', '.xlsx')
delExtension = nessusCSV_xlsx.replace('.csv', ' ')
xwb = xlsxwriter.Workbook(nessusCSV_xlsx)
xwsc = xwb.add_worksheet(name = "Critical")
xwsc.set_tab_color('#FF0000')
xwsh = xwb.add_worksheet(name = "High")
xwsh.set_tab_color('#FF6600')
xwsm = xwb.add_worksheet(name = "Medium")
xwsm.set_tab_color('#FFFF00')
xwsl = xwb.add_worksheet(name = "Low")
xwsl.set_tab_color('#008000')
xwsi = xwb.add_worksheet(name = "Informational")
xwsi.set_tab_color('#0000FF')
xws = xwb.add_worksheet(name = "Raw Data")
xws.set_tab_color('#00FF00')
xformat = xwb.add_format()
xformat.set_align('center') 
headerFormat = xwb.add_format({'bold': True, 'font_color': 'white', 'bg_color': 'black', 'align': 'center' })

open4Extract = open('templateGenerator.csv', 'rb')
parseExtract = csv.reader(open4Extract)

rowHeaders = ['Plugin ID', 'CVE', 'CVSS', 'Risk', 'Host', 'Protocol', 'Port', 'Name', 'Synopsis', 'Description', 'Solution', 'See Also', 'Plugin Output']
row = 0
col = 0
xws.write_row(row, col, tuple(rowHeaders), headerFormat)
xwsc.write_row(row, col, tuple(rowHeaders), headerFormat)
xwsh.write_row(row, col, tuple(rowHeaders), headerFormat)
xwsm.write_row(row, col, tuple(rowHeaders), headerFormat)
xwsl.write_row(row, col, tuple(rowHeaders), headerFormat)
xwsi.write_row(row, col, tuple(rowHeaders), headerFormat)

var5 = 1
for row in parseExtract:
	if ("Critical" in row or "High" in row or "Medium" in row or "Low" in row or "None" in row):
		xws.write_row(var5, 0, row, xformat)
		var5 += 1



read_critical = open(import_nessusCSV, 'rb')
extractCritical = csv.reader(read_critical)
c = 1
for row in extractCritical:
	if ("Critical" in row):
		xwsc.write_row(c, 0, row, xformat)
		c += 1
read_critical.close()



read_critical = open(import_nessusCSV, 'rb')
extractHigh = csv.reader(read_critical)
h = 1
for row in extractHigh:
	if ("High" in row):
		xwsh.write_row(h, 0, row, xformat)
		h += 1
read_critical.close()



read_critical = open(import_nessusCSV, 'rb')
extractMedium = csv.reader(read_critical)
m = 1
for row in extractMedium:
	if ("Medium" in row):
		xwsm.write_row(m, 0, row, xformat)
		m += 1
read_critical.close()



read_critical = open(import_nessusCSV, 'rb')
extractLow = csv.reader(read_critical)
l = 1
for row in extractLow:
	if ("Low" in row):
		xwsl.write_row(l, 0, row, xformat)
		l += 1
read_critical.close()



read_critical = open(import_nessusCSV, 'rb')
extractInfo = csv.reader(read_critical)
i = 1
for row in extractInfo:
	if ("None" in row):
		xwsi.write_row(i, 0, row, xformat)
		i += 1
read_critical.close()



xwb.close()
os.remove('templateGenerator.csv')


#END

