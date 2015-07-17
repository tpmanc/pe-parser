<?php

namespace Classes;

use Classes\DosHeader;
use Classes\PEHeader\PEHeader;

class Parser
{
    /**
     * @var array Массив с информацией о файле
     */
    private $result = [];

    public function parse($fileName)
    {
        $handle = fopen($fileName, 'rb');
        if (!$handle) {
            echo 'file not open';
            return false;
        }

        // DOS HEADER
        $header = fread ($handle, DosHeader::LENGTH);
        $dosHeader = new DosHeader($header);
        $this->result['DosHeader'] = $dosHeader->getInfo();
        $peOffset = $this->result['DosHeader']['PEOffset'];

        // PE HEADER
        fseek($handle, $peOffset, SEEK_SET);
        $header = fread($handle, PEHeader::LENGTH);
        $peHeader = new PEHeader($header);
        $this->result['PeHeader'] = $peHeader->getInfo();


        return $this->result;
    }
}