<?php
/**
 * @author tpmanc
 */

namespace Classes\PEHeader;

/**
 * 16-битовое число, которое задает архитектуру процессора, на которой может выполняться данная программа
 * @package Classes\PEHeader
 */
class Machines
{
    private static $machines = [
        '014C' => ['title' => 'Intel 80386 или выше'],
        '014D' => ['title' => ''],
        '014E' => ['title' => ''],
        '0160' => ['title' => ''],
        '0162' => ['title' => ''],
        '0166' => ['title' => ''],
        '0168' => ['title' => ''],
        '0169' => ['title' => ''],
        '0184' => ['title' => ''],
        '01A2' => ['title' => ''],
        '01A3' => ['title' => ''],
        '01A4' => ['title' => ''],
        '01A6' => ['title' => ''],
        '01A8' => ['title' => ''],
        '01C0' => ['title' => ''],
        '01C2' => ['title' => ''],
        '01D3' => ['title' => ''],
        '01F0' => ['title' => ''],
        '01F1' => ['title' => ''],
        '0200' => ['title' => ''],
        '0266' => ['title' => ''],
        '0268' => ['title' => ''],
        '0284' => ['title' => ''],
        '0290' => ['title' => ''],
        '0366' => ['title' => ''],
        '0466' => ['title' => ''],
        '0520' => ['title' => ''],
        '0EBC' => ['title' => ''],
        '8664' => ['title' => 'asd'],
        '9041' => ['title' => ''],
    ];

    public static function getTitle($code)
    {
        if (isset(self::$machines[$code])) {
            return self::$machines[$code]['title'];
        }
        return 'Неизвестный процессор';
    }
}