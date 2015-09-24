<?php

namespace Mdanter\X509\Extensions\Extension;

use Mdanter\X509\Extensions\MultiValuedExtension;

class KeyUsage extends MultiValuedExtension
{
    /**
     * @var resource
     */
    private $bits;

    /**
     * @param null|bool $critical
     */
    public function __construct($critical)
    {
        parent::__construct($critical);
        $this->bits = gmp_init(0);
    }

    /**
     * @param int $usageIndicator
     */
    public function addKeyUsage($usageIndicator)
    {
        if (!($usageIndicator >= 0 && $usageIndicator < 8)) {
            throw new \InvalidArgumentException;
        }

        gmp_setbit($this->bits, $usageIndicator);
    }

    /**
     * @return string
     */
    public function getBitString()
    {
        return str_pad(gmp_strval($this->bits, 2), '8', '0', STR_PAD_LEFT);
    }

    /**
     * @return array
     */
    public function getValues()
    {
        $values = [];
        for ($i = 0; $i < 8; $i++) {
            if (gmp_testbit($this->bits, $i)) {
                $values[] = $i;
            }
        }

        return $values;
    }
}
