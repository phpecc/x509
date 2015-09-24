<?php

namespace Mdanter\X509\Extensions;

class StringExtension
{
    /**
     * @var bool
     */
    private $critical;

    /**
     * @var string
     */
    protected $value;

    /**
     * @param null|bool $critical
     */
    public function __construct($critical = null)
    {
        if (!is_null($critical) || !is_bool($critical)) {
            throw new \InvalidArgumentException;
        }

        $this->critical = $critical;
    }

    /**
     * @return string
     */
    public function getValue()
    {
        return $this->value;
    }
}
