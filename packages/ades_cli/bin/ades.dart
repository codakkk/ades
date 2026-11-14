import 'dart:io';

import 'package:ades_cli/ades_cli.dart';

Future<void> main(List<String> args) async {
  exitCode = await runCli(args, env: CliEnvironment.system());
}
