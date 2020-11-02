// SPDX-License-Identifier: GPL-2.0-or-later
/*
* www/assets/js/wfp.c
*
* SCANOSS Javascript WFP implementation
*
* Copyright (C) 2018-2020 SCANOSS.COM
*
* includes a Javascript implementation of the CRC32 algorithm
* by https://github.com/CatStarwind
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 2 of the License, or
* (at your option) any later version.

* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.

* You should have received a copy of the GNU General Public License
* along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

var makeCRCTable = function(){
	var c;
	var crcTable = [];
	for(var n =0; n < 256; n++){
		c = n;
		for(var k =0; k < 8; k++){
			c = ((c&1) ? (0x82F63B78 ^ (c >>> 1)) : (c >>> 1));
		}
		crcTable[n] = c;
	}
	return crcTable;
}

var crc32 = function(str) {
	var crcTable = window.crcTable || (window.crcTable = makeCRCTable());
	var crc = 0 ^ (-1);

	for (var i = 0; i < str.length; i++ ) {
		crc = (crc >>> 8) ^ crcTable[(crc ^ str.charCodeAt(i)) & 0xFF];
	}

	return (crc ^ (-1)) >>> 0;
}

var crc32_of_int32 = function(int32) {
	var crcTable = window.crcTable || (window.crcTable = makeCRCTable());
	var crc = 0 ^ (-1);

	var d1 = int32 % 256;
	var d2 = ((int32 - d1) % 65536) / 256;
	var d3 = ((int32 - d1 - d2 * 256) % 16777216) / 65536 ;
	var d4 = (int32 - d1 - d2 * 256 - d3 * 65536) / 16777216;

	crc = (crc >>> 8) ^ crcTable[(crc ^ d1) & 0xFF];
	crc = (crc >>> 8) ^ crcTable[(crc ^ d2) & 0xFF];
	crc = (crc >>> 8) ^ crcTable[(crc ^ d3) & 0xFF];
	crc = (crc >>> 8) ^ crcTable[(crc ^ d4) & 0xFF];

	return (crc ^ (-1)) >>> 0;
}

/* Converts a numeric hash to hex */
var hex_hash = function(crc)
{
	return crc.toString(16).padStart(8, '0');
}

/* Convert case to lowercase, and return zero if it isn't a letter or number
   Do it fast and independent from the locale configuration (avoid string.h) */
var normalize = function(Byte)
{
	if (Byte < "0")  return "";
	if (Byte > "z")  return "";
	if (Byte <= "9")  return Byte;
	if (Byte >= "a") return Byte;
	if ((Byte >= "A") && (Byte <= "Z")) return Byte.toLowerCase();
	return "";
}

var calc_wfp = function(src) {

	var src_len = src.length;
	out = "file=00000000000000000000000000000000," + src_len + ",pasted.wfp\n";

	var hash = Math.pow(2,32);
	var last = 0;
	var line = 1;
	var last_line = 0;
	var counter = 0;
	var limit = 5000;
	var window_ptr = 0;
	var gram = "";

	var Window = [];
	for (i = 0; i < WINDOW; i++) Window.push(hash);

	var GRAM = 30;   // Winnowing gram size in bytes
	var WINDOW = 64; // Winnowing window size in bytes

	for (var i = 0; i < src_len; i++)
	{
		if (src[i] === '\n') line++;

		var Byte = normalize(src[i]);
		if (Byte == "") continue;

		// Add byte to the gram 
		gram += Byte;

		// Got a full gram? 
		if (gram.length >= GRAM)
		{
			// Add fingerprint to the window
			Window[window_ptr++] = crc32(gram);

			// Got a full window? 
			if (window_ptr >= WINDOW)
			{
				/* Select smaller hash for the given window */
				var hash = Math.pow(2, 32);
				for (var W = 0; W < Window.length; W++)
				{
					if (Window[W] < hash) hash = Window[W];
				}

				if (hash != last)
				{
					/*  Hashing the hash will result in a better balanced resulting data set
				as it will counter the winnowing effect which selects the "minimum"
				hash in each window */

					crc_of_crc = crc32_of_int32(hash);
					if (line != last_line)
					{
						if (last_line > 0) out += "\n";
						out += line + "=" + hex_hash(crc_of_crc);
						last_line = line;
					}
					else
					{
						out += "," + hex_hash(crc_of_crc);
					}

					counter++;
					last = hash;
				}

				if (counter >= limit) break;

				/* Shift Window elements left */
				for (var w = 0; w < (WINDOW - 1); w++)
				{
					Window[w] = Window[w + 1];
				}
				window_ptr = WINDOW - 1;
				Window[window_ptr] = Math.pow(2,32);
			}

			/* Shift gram left */
			gram = gram.substring(1, GRAM);
		}
	}
	return out;
}

var plain_english_sbom = function(vendor, component, version, latest, file, lines, license, copyright, url)
{
	var result = "The code pasted above is found in lines <b>" + lines;
	result += "</b> of the file <b>" + file;
	result += "</b> which is part of the component <b>" + component;
	if (version == latest)
		result += "</b> version <b>" + version + "</b>";
	else
		result += "</b> versions <b>" + version + " - " + latest + "</b>";
	result += "</b> published by <b>" + vendor;
	if (license) result += "</b> licensed under <b>" + license;
	if (copyright) result += "</b> with <b>" + copyright;
	result += "</b>. The original work is available <a href='" + url + "' target='_blank'>here</a>";
	return result;
}

var csv_sbom = function(vendor, component, version, latest, file, lines, license, copyright, url)
{
	var result = vendor + "," + component + "," + version + "," + latest + "," + file + "," + lines + "," + license + "," + copyright + "," + url;
	return result;
}

function scan(wfp)
{
	var url = "/api/scan/direct";
	var request = new XMLHttpRequest();

	request.onload = function () {
		var status = request.status;
		var results = JSON.parse(request.responseText);

		/* No results */
		if (results["pasted.wfp"][0]["id"] == "none")
		{
			document.getElementById("results").innerHTML = "<p>Sorry, that did not ring any bells. However, the OSSKB is at an early stage and we are adding information every day. Please come back soon and check again</p>";
		}
		else 
		{
			var license = "";
			var copyright = "";
			if (results["pasted.wfp"][0]["licenses"].length) license = results["pasted.wfp"][0]["licenses"][0]["name"];
			if (results["pasted.wfp"][0]["copyrights"].length) copyright = results["pasted.wfp"][0]["copyrights"][0]["name"];
			var vendor = results["pasted.wfp"][0]["vendor"];
			var component = results["pasted.wfp"][0]["component"];
			var version = results["pasted.wfp"][0]["version"];
			var latest = results["pasted.wfp"][0]["latest"];
			var lines = results["pasted.wfp"][0]["oss_lines"];
			var file = results["pasted.wfp"][0]["file"];
			var url = results["pasted.wfp"][0]["url"];

			document.getElementById("results").innerHTML = plain_english_sbom(vendor, component, version, latest, file, lines, license, copyright, url);
			document.getElementById("csv").innerHTML = csv_sbom(vendor, component, version, latest, file, lines, license, copyright, url);
		}

	}

	request.open("POST", url, true);
	request.setRequestHeader("User-Agent", "osskb.org/1.00");
	request.setRequestHeader("Content-Type", "multipart/form-data; boundary=------------------------scanoss_wfp_scan");
	var postData = "--------------------------scanoss_wfp_scan\r\n";
	postData += "Content-Disposition: form-data; name=\"file\"; filename=\"pasted.wfp\"\r\n";
	postData += "Content-Type: application/octet-stream\r\n"+"\r\n";
	postData += wfp;
	postData += "\r\n--------------------------scanoss_wfp_scan--\r\n\r\n";

	request.send(postData);
}

function sbom(wfp, format, url)
{
	var request = new XMLHttpRequest();

	request.onload = function () {
		var status = request.status;
		var results = JSON.parse(request.responseText);
		document.getElementById(format).innerHTML = request.responseText;
	}

	request.open("POST", url, true);

	request.setRequestHeader("User-Agent", "osskb.org/1.00");
	request.setRequestHeader("Content-Type", "multipart/form-data; boundary=------------------------scanoss_wfp_scan");
	var postData = "--------------------------scanoss_wfp_scan\r\n";
	postData += "Content-Disposition: form-data; name=\"format\"\r\n\r\n";
	postData += format+"\r\n";
	postData += "--------------------------scanoss_wfp_scan\r\n";
	postData += "Content-Disposition: form-data; name=\"file\"; filename=\"pasted.wfp\"\r\n";
	postData += "Content-Type: application/octet-stream\r\n"+"\r\n";
	postData += wfp;
	postData += "\r\n--------------------------scanoss_wfp_scan--\r\n\r\n";

	request.send(postData);
}

function rescan()
{
	var url = "/api/scan/direct";
	var code = $.trim($("#code").val());
	var wfp = "";
	if (code.length == 32) wfp = "file="+code+",999,pasted.wfp";
	else wfp = calc_wfp(code);
	$("#snippets").val(wfp);
	if (code.length > 50 || code.length == 32)
	{
		scan(wfp, url);
		sbom(wfp, "spdx", url);
		sbom(wfp, "cyclonedx", url);
	}
	else
	{
		document.getElementById("results").innerHTML = "<p>Note that only your code hashes are submitted to the OSSKB. Also, please keep in mind that the OSSKB contains only software. Therefore, you will not see matches to media files, configuration files, or any content that is not software in source code or binary form.</p>";
	}
}
