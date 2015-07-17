<?php
/**
 * @author tpmanc
 */

namespace Classes\PEHeader;

use Classes\PEHeader\FileHeader;

/**
 * Заголовок PE (IMAGE_NT_HEADERS) всегда выравнен на границу 8 байт и состоит из трех частей.
 * Длина 24 байта
 * Заголовок PE всегда начинается с 4-байтовой сигнатуры "PE\0\0" (IMAGE_NT_SIGNATURE)
 * За ней следуют два заголовка: заголовок файла (IMAGE_FILE_HEADER) и необязательный заголовок (IMAGE_OPTIONAL_HEADER)
 * @package Classes
 */
class PEHeader
{
    /**
     * Длина заголовка PE
     */
    const LENGTH = 24;

    /**
     * Значение сигнатуры
     */
    const SIGNATURE_VALUE = "PE\0\0";

    /**
     * @var array Заголовок PE всегда начинается с 4-байтовой сигнатуры "PE\0\0" (IMAGE_NT_SIGNATURE)
     */
    private $signature = [
        'offset' => 0,
        'length' => 4,
    ];

    /**
     * @var string Строка с заголовком PE
     */
    private $header;

    /**
     * @var \Classes\PEHeader\FileHeader
     */
    private $fileHeader;

    public function __construct($header)
    {
        $this->header = $header;
        $fileHeader = substr($this->header, $this->signature['length']);
        $this->fileHeader = new FileHeader($fileHeader);
    }

    /**
     * Проверка сигнатуры а равенство "PE"
     * @return string Значение сигнатуры
     * @throws \Exception Сигнатура не равна "PE"
     */
    private function getSignature()
    {
        $sig = substr($this->header, $this->signature['offset'], $this->signature['length']);
        if ($sig !== self::SIGNATURE_VALUE) {
            throw new \Exception('Сигнатура не равна "PE"');
        }
        return self::SIGNATURE_VALUE;
    }

    /**
     * Получение всей информации из PE HEADER
     * @return array
     */
    public function getInfo()
    {
        $info = [];
        $info['Signature'] = $this->getSignature();
        $info['Machine'] = $this->fileHeader->getMachine();
        $info['NumberOfSections'] = $this->fileHeader->getNumberOfSections();
        $info['TimeDateStamp'] = $this->fileHeader->getTimeDateStamp();
        $info['PointerToSymbolTable'] = $this->fileHeader->getPointerToSymbolTable();
        $info['NumberOfSymbols'] = $this->fileHeader->getNumberOfSymbols();
        $info['SizeOfOptionalHeader'] = $this->fileHeader->getSizeOfOptionalHeader();
        $info['Characteristics'] = $this->fileHeader->getCharacteristics();

        return $info;
    }
}