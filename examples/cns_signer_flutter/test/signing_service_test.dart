import 'dart:io';
import 'dart:typed_data';

import 'package:ades/ades.dart';
import 'package:ades_soft/ades_soft.dart';
import 'package:cns_signer_example/signing_service.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  final tier1 = '../../fixtures/tier1';

  test('IsolateFileSigner writes a .p7m the core validates', () async {
    final dir = Directory.systemTemp.createTempSync('cns_sign');
    addTearDown(() => dir.deleteSync(recursive: true));
    final input = File('${dir.path}/hello.txt')
      ..writeAsBytesSync(File('$tier1/content/hello.txt').readAsBytesSync());
    final out = '${input.path}.p7m';
    final cred = SoftSigningCredential.fromPkcs12(
      File('$tier1/pki/rsa2048/leaf-qsign.p12').readAsBytesSync(),
      password: 'test',
    );

    await const IsolateFileSigner().signEnveloping(
      inputPath: input.path,
      outputPath: out,
      credential: cred,
    );

    final report = await Validator(
      trustAnchors: [
        TrustAnchor.fromDer(
          File('$tier1/pki/rsa2048/leaf-qsign.der').readAsBytesSync(),
        ),
      ],
    ).validate(Uint8List.fromList(File(out).readAsBytesSync()));
    final d = report.detailed.signatures.single;
    expect(
      d.result(BuildingBlock.cryptographicVerification)!.indication,
      BlockIndication.passed,
    );
    expect(File('$out.part').existsSync(), isFalse);
  });
}
