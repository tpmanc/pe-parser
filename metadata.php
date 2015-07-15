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
	$peOffset = unpack("v", substr($header, 60, 4));
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
	$machine = unpack("v", substr($header, 0, 2))[1]; // Обозначение процессора.
	$numberOfSection = unpack("v", substr($header, 2, 2))[1];
	$timeDateStamp = unpack("v", substr($header, 4, 4))[1];
	$pointerToSymbolTable = unpack("v", substr($header, 8, 4))[1];
	$numberOfSymbols = unpack("v", substr($header, 12, 4))[1];
	$sizeOfOptionalHeader = unpack("v", substr($header, 16, 2))[1];
	$characteristics = unpack("v", substr($header, 18, 2))[1];
	echo dechex($machine), '<br>';
	echo $numberOfSection, '<br>';
	echo dechex($timeDateStamp), '<br>';
	echo $pointerToSymbolTable, '<br>';
	echo $numberOfSymbols, '<br>';
	echo dechex($sizeOfOptionalHeader), '<br>';
	echo dechex($characteristics), '<br>';

	$NoSections = unpack("v", substr($header, 6, 2));
	$OptHdrSize = unpack("v", substr($header, 20, 2));
	fseek($handle, $OptHdrSize[1], SEEK_CUR);
	$ResFound = false;
	for ($x = 0; $x < $NoSections[1]; $x++) {
		$SecHdr = fread($handle, 40);
		if (substr($SecHdr, 0, 5) == '.rsrc') {         //resource section
			$ResFound = true;
			break;
		}
	}

	if (!$ResFound) {
		echo 'res found';
		return false;
	}
	$InfoVirt = unpack("V", substr($SecHdr, 12, 4));
	$InfoSize = unpack("V", substr($SecHdr, 16, 4));
	$InfoOff = unpack("V", substr($SecHdr, 20, 4));
	fseek($handle, $InfoOff[1], SEEK_SET);
	$Info = fread($handle, $InfoSize[1]);
	$NumDirs = unpack("v", substr($Info, 14, 2));
	$InfoFound = false;
	for ($x = 0; $x < $NumDirs[1]; $x++) {
		$Type = unpack("V", substr($Info, ($x*8)+16, 4));
		if($Type[1] == 16) { //FILEINFO resource
			$InfoFound = true;
			$SubOff = unpack("V", substr($Info, ($x*8)+20, 4));
			//echo $Info;
			break;
		}
	}
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
	return $Version;
	*/

	//view data...
	//echo print_r(explode("\x00\x00\x00", $Info));
	// could prolly substr on VS_VERSION_INFO
	$encodedKey = implode("\x00",str_split($seeking));
	$StartOfSeekingKey = strpos($Info, $encodedKey);
	if ($StartOfSeekingKey !== false) {
			$ulgyRemainderOfData = substr($Info, $StartOfSeekingKey);

			$ArrayOfValues = explode("\x00\x00\x00", $ulgyRemainderOfData);
			// the key your are seeking is 0, where the value is one
			return trim($ArrayOfValues[1]);
	}

	return false;
}


$fileVersion = GetValueOfSeeking('/var/www/iexplore.exe', 'FileVersion');

var_dump($fileVersion);