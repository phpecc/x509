<?php

require "../vendor/autoload.php";


use Mdanter\Ecc\Serializer\PublicKey\DerPublicKeySerializer;
use Mdanter\X509\Serializer\Certificates\CertificateSubjectSerializer;
use Mdanter\X509\Serializer\Signature\DerSignatureSerializer;

$curveName = 'secp256k1';
$hasherName = 'sha512';
$serialNo = 0;

$math = \Mdanter\Ecc\EccFactory::getAdapter();
$f = new \Mdanter\X509\Factory();
$domain = $f->getDomain($math, $curveName, $hasherName);
$G = $domain->getGenerator();

$randomInt = \Mdanter\Ecc\Random\RandomGeneratorFactory::getUrandomGenerator()->generate($G->getOrder());
$k = $G->getPrivateKeyFrom($randomInt);

$issuerDetails = [
    'commonName' => 'test CA'
];
$issuerSubject = new \Mdanter\X509\Certificates\CertificateSubject($issuerDetails);

$ca = $f->getCA($math, $domain, $issuerSubject);

$serializer = new \Mdanter\X509\Serializer\Certificates\CertificateSerializer(new CertificateSubjectSerializer(), new DerPublicKeySerializer(), new DerSignatureSerializer());

$validityStart = new DateTime('now');
$validityEnd = new DateTime('now');
$validityEnd->modify("+1 year");

$info = new \Mdanter\X509\Certificates\CertificateInfo(
    0,
    $domain->getSigAlgorithm(),
    $issuerSubject,
    $issuerSubject,
    $k->getPublicKey(),
    $validityStart,
    $validityEnd
);

$usage = new \Mdanter\X509\Extensions\Extension\KeyUsage(null);
$usage->addKeyUsage(0);
$usage->addKeyUsage(1);
$usage->addKeyUsage(5);
var_dump($usage->getBitString());


$certificate = $ca->createCertificate($serializer, $info, $k);


echo $serializer->serialize($certificate);
