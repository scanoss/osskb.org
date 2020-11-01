// SPDX-License-Identifier: GPL-2.0-or-later
/*
* wfp.js
*
* Calculation of wfp hashes for SCANOSS identification
* Copyright (C) SCANOSS 2018-2020
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
	out = "file=" + md5(src) + "," + src_len + ",pasted.wfp\n";

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

