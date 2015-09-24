<?php

namespace Mdanter\X509\Extensions\Extension;

use Mdanter\X509\Extensions\MultiValuedExtension;

class BasicConstraints extends MultiValuedExtension
{
    /**
     * @var array
     */
    protected $values;

    /**
     * @param bool $critical
     */
    public function __construct($critical)
    {
        parent::__construct($critical);
    }

    /**
     * @param bool $isCa
     */
    public function addCaFlag($isCa)
    {
        if (!is_bool($isCa)) {
            throw new \InvalidArgumentException('BasicConstraint: must provide a boolean');
        }

        $this->values['CA'] = $isCa;
    }

    /**
     * @param int $pathLength
     */
    public function addPathLenConstraint($pathLength)
    {
        if (!is_numeric($pathLength)) {
            throw new \InvalidArgumentException('BasicConstraint: path length must be numeric');
        }

        $this->values['pathlen'] = $pathLength;
    }
}
