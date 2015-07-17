<?php
/**
 * @author tpmanc
 */

namespace Classes\PEHeader;

use Classes\PEHeader\Machines;

/**
 * Заголовок файла состоит из 0x14 байтов (определение IMAGE_SIZEOF_FILE_HEADER),
 * размещается сразу после сигнатуры и содержит общее описание файла.
 * @package Classes\PEHeader
 */
class FileHeader
{
    /**
     * Длина заголовка файла
     */
    const LENGTH = 20;

    /**
     * @var string Строка с заголовком файла
     */
    private $header;

    /**
     * @var array Обозначение процессора
     */
    private $machine = [
        'offset' => 0x00,
        'length' => 2,
    ];

    /**
     * @var array Количество секций в файле
     */
    private $numberOfSections = [
        'offset' => 0x02,
        'length' => 2,
    ];

    /**
     * @var array Дата и время создания файла
     */
    private $timeDateStamp = [
        'offset' => 0x04,
        'length' => 4,
    ];

    /**
     * @var array Смещение до таблицы символов или 0
     */
    private $pointerToSymbolTable = [
        'offset' => 0x08,
        'length' => 4,
    ];

    /**
     * @var array Количество элементов в таблице символов
     */
    private $numberOfSymbols = [
        'offset' => 0x0C,
        'length' => 4,
    ];

    /**
     * @var array Размер необязательного заголовка
     */
    private $sizeOfOptionalHeader = [
        'offset' => 0x10,
        'length' => 2,
    ];

    /**
     * @var array Атрибуты файла
     */
    private $characteristics = [
        'offset' => 0x12,
        'length' => 2,
    ];

    public function __construct($header)
    {
        $this->header = $header;
    }

    /**
     * Получение обозначения процессора
     * @return integer
     */
    public function getMachine()
    {
        $machine = substr($this->header, $this->machine['offset'], $this->machine['length']);
        $machine = unpack('v', $machine)[1];
        return $machine;
    }

    /**
     * Получение количества секций в файле
     * @return integer
     */
    public function getNumberOfSections()
    {
        $numberOfSections = substr($this->header, $this->numberOfSections['offset'], $this->numberOfSections['length']);
        $numberOfSections = unpack('v', $numberOfSections)[1];
        return $numberOfSections;
    }

    /**
     * Получение даты и времени создания файла
     * @return integer
     */
    public function getTimeDateStamp()
    {
        $timeDateStamp = substr($this->header, $this->timeDateStamp['offset'], $this->timeDateStamp['length']);
        $timeDateStamp = unpack('v', $timeDateStamp)[1];
        return $timeDateStamp;
    }

    /**
     * Смещение до таблицы символов или 0
     * @return integer
     */
    public function getPointerToSymbolTable()
    {
        $pointerToSymbolTable = substr($this->header, $this->pointerToSymbolTable['offset'], $this->pointerToSymbolTable['length']);
        $pointerToSymbolTable = unpack('v', $pointerToSymbolTable)[1];
        return $pointerToSymbolTable;
    }

    /**
     * Количество элементов в таблице символов
     * @return integer
     */
    public function getNumberOfSymbols()
    {
        $numberOfSymbols = substr($this->header, $this->numberOfSymbols['offset'], $this->numberOfSymbols['length']);
        $numberOfSymbols = unpack('v', $numberOfSymbols)[1];
        return $numberOfSymbols;
    }

    /**
     * Размер необязательного заголовка
     * @return integer
     */
    public function getSizeOfOptionalHeader()
    {
        $sizeOfOptionalHeader = substr($this->header, $this->sizeOfOptionalHeader['offset'], $this->sizeOfOptionalHeader['length']);
        $sizeOfOptionalHeader = unpack('v', $sizeOfOptionalHeader)[1];
        return $sizeOfOptionalHeader;
    }

    /**
     * Атрибуты файла
     * @return integer
     */
    public function getCharacteristics()
    {
        $characteristics = substr($this->header, $this->characteristics['offset'], $this->characteristics['length']);
        $characteristics = unpack('v', $characteristics)[1];
        return $characteristics;
    }
}