<?php

require "../vendor/autoload.php";

$curveName = 'nist-p521';
$hashAlgo = 'sha256';
$factory = new Mdanter\X509\Factory();
$adapter = \Mdanter\Ecc\EccFactory::getAdapter();

$domain = $factory->getDomain($adapter, $curveName, $hashAlgo);


$rbg = \Mdanter\Ecc\Random\RandomGeneratorFactory::getUrandomGenerator();
$G = \Mdanter\Ecc\Curves\CurveFactory::getGeneratorByName($curveName);

$randomInt = $rbg->generate($G->getOrder());
$k = $G->getPrivateKeyFrom($randomInt);
$Q = $k->getPublicKey();

$subjectDetails = [
    'commonName' => '127.0.0.1'
];

$subject = new Mdanter\X509\Certificates\CertificateSubject($subjectDetails);

$csr = $factory->getCsr($domain, $subject, $k);
$csrSerializer = new \Mdanter\X509\Serializer\Certificates\CsrSerializer(
    new \Mdanter\X509\Serializer\Certificates\CertificateSubjectSerializer(),
    new \Mdanter\Ecc\Serializer\PublicKey\DerPublicKeySerializer($adapter),
    new \Mdanter\X509\Serializer\Signature\DerSignatureSerializer()
);

$serialized = $csrSerializer->serialize($csr);
echo $serialized;