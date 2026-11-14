import 'dart:typed_data';

import 'package:ades/ades.dart';
import 'package:ades_pkcs11/ades_pkcs11.dart';
import 'package:cns_signer_example/card_source.dart';
import 'package:cns_signer_example/main.dart';
import 'package:cns_signer_example/signing_service.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

class _FakeCredential extends SigningCredential {
  _FakeCredential(this.onPin);
  final PinCallback onPin;

  @override
  Future<Uint8List> get certificate async => Uint8List(0);

  @override
  List<SignatureAlgorithm> get supportedAlgorithms => const [];

  @override
  Future<SignatureValue> sign(SignRequest request) async {
    final pin = await onPin(
      const PinRequest(slotId: 1, tokenLabel: 'CNS', credentialLabel: 'Firma'),
    );
    if (pin == null) throw const Pkcs11PinCancelledException('cancelled');
    return SignatureValue.raw(Uint8List.fromList([1, 2, 3]));
  }
}

class _FakeSource implements CardSource {
  bool empty = false;

  @override
  Future<CardSession> open({required PinCallback onPin}) async {
    if (empty) throw const NoMiddlewareException('nothing installed');
    return _FakeSession([
      CredentialChoice(
        id: 'a',
        label: 'Firma',
        tokenLabel: 'CNS',
        kind: CredentialKind.qualifiedSignature,
        credential: _FakeCredential(onPin),
      ),
      CredentialChoice(
        id: 'b',
        label: 'Autenticazione',
        tokenLabel: 'CNS',
        kind: CredentialKind.authentication,
        credential: _FakeCredential(onPin),
      ),
    ]);
  }
}

class _FakeSession implements CardSession {
  _FakeSession(this.credentials);
  @override
  final List<CredentialChoice> credentials;
  @override
  String get discoverySummary => 'found: Fake at /fake.so';
  @override
  Future<void> close() async {}
}

class _FakeSigner implements FileSigner {
  final signed = <(String, String)>[];

  @override
  Future<void> signEnveloping({
    required String inputPath,
    required String outputPath,
    required SigningCredential credential,
  }) async {
    await credential.sign(
      SignRequest(
        dtbs: Uint8List(1),
        dtbsr: Uint8List(1),
        signatureAlgorithm: SignatureAlgorithm.rsaPkcs1v15Sha256,
      ),
    );
    signed.add((inputPath, outputPath));
  }
}

Future<void> _pumpApp(
  WidgetTester tester,
  _FakeSource source,
  _FakeSigner signer,
) => tester.pumpWidget(
  CnsSignerApp(
    source: source,
    signer: signer,
    pickFile: () async => '/tmp/doc.pdf',
  ),
);

String _status(WidgetTester t) =>
    t.widget<Text>(find.byKey(const Key('status'))).data!;

void main() {
  testWidgets('pick, read card, list credentials, PIN, sign', (tester) async {
    final signer = _FakeSigner();
    await _pumpApp(tester, _FakeSource(), signer);

    // Sign is disabled until a file and a credential are chosen.
    expect(
      tester
          .widget<FilledButton>(
            find.widgetWithText(FilledButton, 'Sign (.p7m)'),
          )
          .onPressed,
      isNull,
    );

    await tester.tap(find.text('Pick file'));
    await tester.pumpAndSettle();
    expect(find.text('/tmp/doc.pdf'), findsOneWidget);

    await tester.tap(find.text('Read card'));
    await tester.pumpAndSettle();
    expect(find.text('Firma'), findsOneWidget);
    expect(find.text('Autenticazione'), findsOneWidget);
    expect(find.textContaining('qualified signature'), findsOneWidget);
    expect(find.textContaining('authentication'), findsWidgets);

    await tester.tap(find.text('Sign (.p7m)'));
    await tester.pump(const Duration(milliseconds: 500));
    expect(find.text('PIN for CNS'), findsOneWidget);
    await tester.enterText(find.byKey(const Key('pin-field')), '1234');
    await tester.tap(find.text('OK'));
    await tester.pumpAndSettle();

    expect(signer.signed, [('/tmp/doc.pdf', '/tmp/doc.pdf.p7m')]);
    expect(_status(tester), 'Written /tmp/doc.pdf.p7m');
  });

  testWidgets('cancelling the PIN dialog signs nothing', (tester) async {
    final signer = _FakeSigner();
    await _pumpApp(tester, _FakeSource(), signer);
    await tester.tap(find.text('Pick file'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Read card'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Sign (.p7m)'));
    await tester.pump(const Duration(milliseconds: 500));
    await tester.tap(find.text('Cancel'));
    await tester.pumpAndSettle();
    expect(signer.signed, isEmpty);
    expect(_status(tester), 'Cancelled.');
  });

  testWidgets('no middleware is explained, with the discovery details', (
    tester,
  ) async {
    await _pumpApp(tester, _FakeSource()..empty = true, _FakeSigner());
    await tester.tap(find.text('Read card'));
    await tester.pumpAndSettle();
    expect(_status(tester), 'No card middleware found.');
    expect(find.text('nothing installed'), findsOneWidget);
  });
}
