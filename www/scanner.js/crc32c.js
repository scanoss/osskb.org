// SPDX-License-Identifier: GPL-2.0-or-later
/*
* crc32c.js
*
* Javascript implementation of the CRC32 algorithm
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
