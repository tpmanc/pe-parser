<?php
ini_set('error_reporting', E_ALL);
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);

function GetValueOfSeeking($FileName){
	$handle = fopen($FileName, 'rb');
	if (!$handle) {
		echo 'file not open';
		return false;
	}

	// IMAGE_DOS_header
	$header = fread ($handle, 64);
	// 2-байтовая (WORD) сигнатура, находящаяся по смещению 0 (e_magic) и равная "MZ" (IMAGE_DOS_SIGNATURE)
	if (substr($header, 0, 2) != 'MZ') {
		echo 'MZ';
		return false;
	}

	// 4-байтовое (DWORD) смещение от начала файла до заголовка PE, находяшееся по смещению 0x3C (e_lfanew)
	// 0x3C - 3C = 60
	$peOffset = unpack("V", substr($header, 60, 4));
	if ($peOffset[1] < 64) { // т.к. IMAGE_DOS_header 64 байта
		echo 'Проблема определения смещения заголовка';
		return false;
	}

	// Заголовок PE (IMAGE_NT_headerS) всегда выравнен на границу 8 байт и состоит из трех частей, всего 24 байта
	fseek($handle, $peOffset[1], SEEK_SET);
	$header = fread($handle, 24);
	// заголовок PE всегда начинается с 4-байтовой сигнатуры "PE\0\0" (IMAGE_NT_SIGNATURE)
	// var_dump(substr($header, 0, 2));
	$signature = substr($header, 0, 2); // IMAGE_NT_SIGNATURE
	if ($signature != 'PE') {
		echo 'PE';
		return false;
	}

	// Заголовок файла состоит из 0x14 = 20 байтов (определение IMAGE_SIZEOF_FILE_header), 
	// размещается сразу после сигнатуры и содержит общее описание файла.
	$header = substr($header, 4, 20);
	$machine = unpack("v", substr($header, 0x00, 2))[1]; // Обозначение процессора.
	$numberOfSection = unpack("v", substr($header, 0x02, 2))[1];
	$timeDateStamp = unpack("V", substr($header, 0x04, 4))[1];
	$pointerToSymbolTable = unpack("V", substr($header, 0x08, 4))[1];
	$numberOfSymbols = unpack("V", substr($header, 0x0C, 4))[1];
	$sizeOfOptionalHeader = unpack("v", substr($header, 0x10, 2))[1];
	$characteristics = unpack("v", substr($header, 0x12, 2))[1];

	// массив заголовков секций
	$NoSections = $numberOfSection;
	$OptHdrSize = $sizeOfOptionalHeader;
	fseek($handle, $OptHdrSize, SEEK_CUR);
	$ResFound = false;
	for ($x = 0; $x < $NoSections; $x++) {
		$SecHdr = fread($handle, 40);
		$re = substr($SecHdr, 0, 5);
		if ($re == '.rsrc') {         //resource section
			$name = substr($SecHdr, 0x00, 8);
			var_dump($name);
			$MiscVirtualSize = dechex(unpack('V', substr($SecHdr, 0x08, 4))[1]);
			var_dump($MiscVirtualSize);
			$VirtualAddress = dechex(unpack('V', substr($SecHdr, 0x0C, 4))[1]);
			var_dump($VirtualAddress);
			$SizeOfRawData = unpack('V', substr($SecHdr, 0x10, 4))[1];
			var_dump(dechex($SizeOfRawData));
			$PointerToRawData = unpack('V', substr($SecHdr, 0x14, 4))[1];
			var_dump(dechex($PointerToRawData));
			$PointerToRelocations = dechex(unpack('V', substr($SecHdr, 0x18, 4))[1]);
			var_dump($PointerToRelocations);
			$PointerToLinenumbers = dechex(unpack('V', substr($SecHdr, 0x1C, 4))[1]);
			var_dump($PointerToLinenumbers);
			$NumberOfRelocations = dechex(unpack('v', substr($SecHdr, 0x20, 2))[1]);
			var_dump($NumberOfRelocations);
			$NumberOfLinenumbers = dechex(unpack('v', substr($SecHdr, 0x22, 2))[1]);
			var_dump($NumberOfLinenumbers);
			$Characteristics = dechex(unpack('V', substr($SecHdr, 0x24, 4))[1]);
			var_dump($Characteristics);
			$ResFound = true;
			break;
		}
	}

	if (!$ResFound) {
		echo 'res found';
		return false;
	}

	fseek($handle, $PointerToRawData, SEEK_SET);
echo '<hr>';
	$sectionInfo = fread($handle, $SizeOfRawData);
	$Characteristics = unpack('V', substr($sectionInfo, 0x00, 4))[1];
	var_dump(dechex($Characteristics));
	$TimeDateStamp = unpack('V', substr($sectionInfo, 0x04, 4))[1];
	var_dump(dechex($TimeDateStamp));
	$MajorVersion = unpack('v', substr($sectionInfo, 0x08, 2))[1];
	var_dump(dechex($MajorVersion));
	$MinorVersion = unpack('v', substr($sectionInfo, 0x0A, 2))[1];
	var_dump(dechex($MinorVersion));
	$NumberOfNamedEntries = unpack('v', substr($sectionInfo, 0x0C, 2))[1];
	var_dump(dechex($NumberOfNamedEntries));
	$NumberOfIdEntries = unpack('v', substr($sectionInfo, 0x0E, 2))[1];
	var_dump(dechex($NumberOfIdEntries));

	for ($i = 0; $i < $NumberOfIdEntries + $NumberOfNamedEntries; $i++) {
		$name = unpack("V", substr($sectionInfo, ($i * 8) + 16, 4))[1];
		// $name = unpack("V", substr($sectionInfo, 14, 4));
		echo '<br>', $name, ' - ';
		var_dump(bin2hex(substr($sectionInfo, ($i * 8) + 16, 4)));
		if ($name == 16) {
			$InfoFound = true;
		}
	}
	
	// $InfoVirt = unpack("V", substr($SecHdr, 12, 4));
	// $InfoSize = unpack("V", substr($SecHdr, 16, 4));
	
	
	// $NumDirs = unpack("v", substr($sectionInfo, 14, 2));
	// var_dump($NumDirs);
	// $InfoFound = false;
	// for ($x = 0; $x < $NumDirs[1]; $x++) {
	// 	$Type = unpack("V", substr($sectionInfo, ($x*8)+16, 4));
	// 	if($Type[1] == 16) { //FILEINFO resource
	// 		$InfoFound = true;
	// 		$SubOff = unpack("V", substr($sectionInfo, ($x*8)+20, 4));
	// 		//echo $Info;
	// 		break;
	// 	}
	// }
	if (!$InfoFound) {
		echo 'info not found';
		return false;
	}

	// i bypassed this, but if you knew the layout you could prolly do a little better then $ulgyRemainderOfData
	/*
	$SubOff[1]&=0x7fffffff;
	$InfoOff=unpack("V",substr($Info,$SubOff[1]+20,4)); //offset of first FILEINFO
	$InfoOff[1]&=0x7fffffff;
	$InfoOff=unpack("V",substr($Info,$InfoOff[1]+20,4));    //offset to data
	$DataOff=unpack("V",substr($Info,$InfoOff[1],4));
	$DataSize=unpack("V",substr($Info,$InfoOff[1]+4,4));
	$CodePage=unpack("V",substr($Info,$InfoOff[1]+8,4));
	$DataOff[1]-=$InfoVirt[1];
	$Version=unpack("v4",substr($Info,$DataOff[1]+48,8));

	// swap 1-2 3-4 / endian ecoding issue
	$x=$Version[2];
	$Version[2]=$Version[1];
	$Version[1]=$x;
	$x=$Version[4];
	$Version[4]=$Version[3];
	$Version[3]=$x;
	var_dump($Version);
	return $Version;
	*/
	

	//view data...
	// echo print_r(explode("\x00\x00\x00", $Info));
	// could prolly substr on VS_VERSION_INFO
	$encodedKey = implode("\x00",str_split('FileVersion'));
	$StartOfSeekingKey = strpos($sectionInfo, $encodedKey);
	if ($StartOfSeekingKey !== false) {
			$ulgyRemainderOfData = substr($sectionInfo, $StartOfSeekingKey);
			// echo $ulgyRemainderOfData;

			$ArrayOfValues = explode("\x00\x00\x00", $ulgyRemainderOfData);
			// echo '<pre>';
			// print_r($ArrayOfValues);
			// the key your are seeking is 0, where the value is one
			return trim($ArrayOfValues[1]);
	}

	return false;
}

// $str = htmlentities(hex2bin('A9'));
// var_dump($str);
$fileVersion = GetValueOfSeeking('/var/www/iexplore.exe', 'FileVersion');

var_dump($fileVersion);
// $fileVersion = GetValueOfSeeking('/var/www/GifCam.exe', 'FileVersion');

// var_dump($fileVersion);