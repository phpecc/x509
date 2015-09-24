<?php

namespace Mdanter\X509\Extensions;

interface ExtensionInterface
{
    /**
     * @return bool
     */
    public function isCriticial();
}
