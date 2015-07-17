<?php
/**
 * @author tpmanc
 */

namespace Classes;

/**
 * Заголовок и заглушка DOS длиной 64 байта.
 * Нас интересуют в нем только два поля.
 *
 * При загрузке PE-файла мы обязаны сначала проверить сигнатуру DOS,
 * затем найти смещение до заголовка PE, а затем проверить сигнатуру PE,
 * расположенную в начале его заголовка.
 * Эта сигнатура состоит из 4 байтов и равна "PE\0\0" (обозначение IMAGE_NT_SIGNATURE)
 * @package Classes
 */
class DosHeader
{
    /**
     * Значение сигнатуры
     */
    const SIGNATURE_VALUE = 'MZ';

    /**
     * Длина заголовка и заглушки DOS
     */
    const LENGTH = 64;

    /**
     * @var array 2-байтовая (WORD) сигнатура, находящаяся по смещению 0 (e_magic) и равная "MZ" (IMAGE_DOS_SIGNATURE)
     */
    private $signature = [
        'offset' => 0,
        'length' => 2,
    ];

    /**
     * @var array 4-байтовое (DWORD) смещение от начала файла до заголовка PE, находяшееся по смещению 0x3C (e_lfanew)
     */
    private $peOffset = [
        'offset' => 0x3C,
        'length' => 4,
    ];

    /**
     * @var string Строка с заголовком и заглушкой DOS
     */
    private $header;

    public function __construct($header)
    {
        $this->header = $header;
    }

    /**
     * Проверка сигнатуры а равенство "MZ"
     * @return string Значение сигнатуры
     * @throws \Exception Сигнатура не равна "MZ"
     */
    private function getSignature()
    {
        $sig = substr($this->header, $this->signature['offset'], $this->signature['length']);
        if ($sig !== self::SIGNATURE_VALUE) {
            throw new \Exception('Сигнатура не равна "MZ"');
        }
        return self::SIGNATURE_VALUE;
    }

    /**
     * Получение смещения до заголовка PE
     * @return bool|int
     * @throws \Exception Проблема определения смещения до заголовка PE
     */
    private function getPeOffset()
    {
        $offset = substr($this->header, $this->peOffset['offset'], $this->peOffset['length']);
        $offset = unpack('v', $offset)[1];
        if ($offset < 64) { // 64 т.к. длина заголовока и заглушки DOS равна 64
            throw new \Exception('Проблема определения смещения до заголовка PE');
        }
        return $offset;
    }

    /**
     * Получение всей информации из DOS HEADER
     * @return array
     */
    public function getInfo()
    {
        $info = [];
        $info['Signature'] = $this->getSignature();
        $info['PEOffset'] = $this->getPeOffset();

        return $info;
    }
}