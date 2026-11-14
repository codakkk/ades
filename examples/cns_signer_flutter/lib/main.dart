import 'package:ades/ades.dart' show AdesException;
import 'package:ades_pkcs11/ades_pkcs11.dart';
import 'package:file_selector/file_selector.dart';
import 'package:flutter/material.dart';

import 'card_source.dart';
import 'signing_service.dart';

void main() => runApp(
  CnsSignerApp(
    source: const Pkcs11CardSource(),
    signer: const IsolateFileSigner(),
    pickFile: () async => (await openFile())?.path,
  ),
);

class CnsSignerApp extends StatelessWidget {
  const CnsSignerApp({
    super.key,
    required this.source,
    required this.signer,
    required this.pickFile,
  });

  final CardSource source;
  final FileSigner signer;
  final Future<String?> Function() pickFile;

  @override
  Widget build(BuildContext context) => MaterialApp(
    title: 'CNS signer',
    theme: ThemeData(colorSchemeSeed: Colors.indigo, useMaterial3: true),
    home: SignerPage(source: source, signer: signer, pickFile: pickFile),
  );
}

class SignerPage extends StatefulWidget {
  const SignerPage({
    super.key,
    required this.source,
    required this.signer,
    required this.pickFile,
  });

  final CardSource source;
  final FileSigner signer;
  final Future<String?> Function() pickFile;

  @override
  State<SignerPage> createState() => _SignerPageState();
}

class _SignerPageState extends State<SignerPage> {
  String? _file;
  CardSession? _session;
  CredentialChoice? _selected;
  String _status = 'Pick a file, then read the card.';
  String? _details;
  bool _busy = false;

  @override
  void dispose() {
    _session?.close();
    super.dispose();
  }

  Future<void> _pick() async {
    final path = await widget.pickFile();
    if (path != null) setState(() => _file = path);
  }

  Future<void> _discover() async {
    setState(() {
      _busy = true;
      _status = 'Looking for card middleware...';
      _details = null;
    });
    try {
      await _session?.close();
      final session = await widget.source.open(onPin: _askPin);
      setState(() {
        _session = session;
        _selected = session.credentials.isEmpty
            ? null
            : session.credentials.first;
        _status = session.credentials.isEmpty
            ? 'Middleware found but no certificates on the card.'
            : '${session.credentials.length} credential(s) found.';
        _details = session.discoverySummary;
      });
    } on NoMiddlewareException catch (e) {
      setState(() {
        _session = null;
        _selected = null;
        _status = 'No card middleware found.';
        _details = e.summary;
      });
    } on Pkcs11Exception catch (e) {
      setState(() => _status = 'Card error: ${e.message}');
    } finally {
      setState(() => _busy = false);
    }
  }

  Future<String?> _askPin(PinRequest r) => showDialog<String>(
    context: context,
    barrierDismissible: false,
    builder: (_) => PinDialog(
      title: 'PIN for ${r.tokenLabel}',
      subtitle: 'Signing with "${r.credentialLabel}"',
    ),
  );

  Future<void> _sign() async {
    final file = _file;
    final choice = _selected;
    if (file == null || choice == null) return;
    setState(() {
      _busy = true;
      _status = 'Signing...';
    });
    try {
      final out = '$file.p7m';
      await widget.signer.signEnveloping(
        inputPath: file,
        outputPath: out,
        credential: choice.credential,
      );
      setState(() => _status = 'Written $out');
    } on Pkcs11PinCancelledException {
      setState(() => _status = 'Cancelled.');
    } on Pkcs11WrongPinException {
      setState(
        () => _status = 'Wrong PIN. Try again (cards lock after a few).',
      );
    } on Pkcs11PinLockedException {
      setState(() => _status = 'PIN is locked. Unblock it with the PUK.');
    } on Pkcs11Exception catch (e) {
      setState(() => _status = 'Card error: ${e.message}');
    } on AdesException catch (e) {
      setState(() => _status = 'Signing failed: ${e.message}');
    } finally {
      setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final session = _session;
    return Scaffold(
      appBar: AppBar(title: const Text('CNS signer (example)')),
      body: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                FilledButton(
                  onPressed: _busy ? null : _pick,
                  child: const Text('Pick file'),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: Text(
                    _file ?? 'No file selected',
                    overflow: TextOverflow.ellipsis,
                  ),
                ),
              ],
            ),
            const SizedBox(height: 12),
            FilledButton.tonal(
              onPressed: _busy ? null : _discover,
              child: const Text('Read card'),
            ),
            const SizedBox(height: 12),
            if (session != null)
              Expanded(
                child: RadioGroup<String>(
                  groupValue: _selected?.id,
                  onChanged: (id) => setState(
                    () => _selected = session.credentials.firstWhere(
                      (c) => c.id == id,
                    ),
                  ),
                  child: ListView(
                    children: [
                      for (final c in session.credentials)
                        RadioListTile<String>(
                          value: c.id,
                          title: Text(c.label),
                          subtitle: Text(
                            '${c.tokenLabel} - ${_kindText(c.kind)}',
                          ),
                        ),
                    ],
                  ),
                ),
              )
            else
              const Spacer(),
            if (_details != null)
              Padding(
                padding: const EdgeInsets.symmetric(vertical: 8),
                child: Text(
                  _details!,
                  style: Theme.of(context).textTheme.bodySmall,
                ),
              ),
            if (_busy) const LinearProgressIndicator(),
            const SizedBox(height: 8),
            Text(_status, key: const Key('status')),
            const SizedBox(height: 8),
            FilledButton(
              onPressed: (_busy || _file == null || _selected == null)
                  ? null
                  : _sign,
              child: const Text('Sign (.p7m)'),
            ),
          ],
        ),
      ),
    );
  }

  static String _kindText(CredentialKind k) => switch (k) {
    CredentialKind.qualifiedSignature => 'qualified signature',
    CredentialKind.authentication => 'authentication',
    CredentialKind.other => 'other',
  };
}

class PinDialog extends StatefulWidget {
  const PinDialog({super.key, required this.title, required this.subtitle});
  final String title;
  final String subtitle;

  @override
  State<PinDialog> createState() => _PinDialogState();
}

class _PinDialogState extends State<PinDialog> {
  final _controller = TextEditingController();

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => AlertDialog(
    title: Text(widget.title),
    content: Column(
      mainAxisSize: MainAxisSize.min,
      children: [
        Text(widget.subtitle),
        TextField(
          key: const Key('pin-field'),
          controller: _controller,
          obscureText: true,
          autofocus: true,
          decoration: const InputDecoration(labelText: 'PIN'),
          onSubmitted: (v) => Navigator.pop(context, v),
        ),
      ],
    ),
    actions: [
      TextButton(
        onPressed: () => Navigator.pop(context),
        child: const Text('Cancel'),
      ),
      FilledButton(
        onPressed: () => Navigator.pop(context, _controller.text),
        child: const Text('OK'),
      ),
    ],
  );
}
