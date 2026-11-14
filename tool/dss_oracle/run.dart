// Runs the pinned DSS oracle (Docker) over fixtures/tier1/oracle-cases.json and
// writes the normalized JSON goldens next to each fixture.
//
//   dart run tool/dss_oracle/run.dart            regenerate goldens in place
//   dart run tool/dss_oracle/run.dart --check    regenerate to a temp dir, exit 1
//                                                if any differs from the committed golden
//   dart run tool/dss_oracle/run.dart --only id  restrict to one case id
//   dart run tool/dss_oracle/run.dart --fixtures dir
//                                                use dir instead of fixtures/tier1
//                                                (needs dir/oracle-cases.json); used
//                                                by the private tier-2 lane, docs/tier2-real-cns.md
//   --check --diff-out DIR   also copy each differing regenerated golden to DIR
//                            (committed goldens are never touched; nightly uploads DIR)
//
// Needs Docker only. The container runs with --network none (DSS is offline).
import 'dart:convert';
import 'dart:io';

Future<void> main(List<String> args) async {
  final check = args.contains('--check');
  final onlyIdx = args.indexOf('--only');
  final only = onlyIdx >= 0 ? args[onlyIdx + 1] : null;

  final diffIdx = args.indexOf('--diff-out');
  final diffOut = diffIdx >= 0 ? args[diffIdx + 1] : null;

  final root = Directory.current.path;
  final fixturesIdx = args.indexOf('--fixtures');
  final fixtures = fixturesIdx >= 0
      ? Directory(args[fixturesIdx + 1]).absolute.path
      : '$root/fixtures/tier1';
  final version = File(
    '$root/tool/dss_oracle/dss_version.txt',
  ).readAsStringSync().trim();
  final image = 'ades-dss-oracle:$version';

  final manifest =
      jsonDecode(File('$fixtures/oracle-cases.json').readAsStringSync())
          as Map<String, dynamic>;
  final time = manifest['validationTime'] as String;
  final cases = [
    for (final c in (manifest['cases'] as List).cast<Map<String, dynamic>>())
      if (only == null || c['id'] == only) c,
  ];

  {
    // always build: Docker's layer cache makes this a no-op when unchanged
    stdout.writeln('building $image ...');
    final build = await Process.start('docker', [
      'build',
      '-t',
      image,
      '$root/tool/dss_oracle',
    ], mode: ProcessStartMode.inheritStdio);
    if (await build.exitCode != 0) exit(1);
  }

  final work = Directory.systemTemp.createTempSync('dss_oracle_');
  try {
    final tsv = StringBuffer();
    for (final c in cases) {
      tsv.writeln(
        [
          c['id'],
          c['signature'],
          c['content'] ?? '-',
          c['anchor'],
          time,
          '-',
          c['policy'] ?? 'default',
        ].join('\t'),
      );
    }
    File('${work.path}/manifest.tsv').writeAsStringSync(tsv.toString());
    Directory('${work.path}/out').createSync();

    final run = await Process.start('docker', [
      'run',
      '--rm',
      '--network',
      'none',
      '-v',
      '$fixtures:/fixtures:ro',
      '-v',
      '${work.path}:/work',
      image,
      '/work/manifest.tsv',
      '/fixtures',
      '/work/out',
    ], mode: ProcessStartMode.inheritStdio);
    if (await run.exitCode != 0) exit(1);

    var differs = 0;
    for (final c in cases) {
      final produced = File('${work.path}/out/${c['id']}.json');
      if (!produced.existsSync()) {
        stderr.writeln('no output for ${c['id']}');
        exit(1);
      }
      if ((jsonDecode(produced.readAsStringSync()) as Map).containsKey(
        'error',
      )) {
        stderr.writeln('DSS harness error for ${c['id']} (see output above)');
        exit(1);
      }
      final target = File('$fixtures/${c['golden']}');
      if (check) {
        if (!target.existsSync() ||
            target.readAsStringSync() != produced.readAsStringSync()) {
          stderr.writeln('DIFFERS: ${c['golden']}');
          if (diffOut != null) {
            final copy = File('$diffOut/${c['golden']}');
            copy.parent.createSync(recursive: true);
            produced.copySync(copy.path);
          }
          differs++;
        }
      } else {
        target.parent.createSync(recursive: true);
        produced.copySync(target.path);
        stdout.writeln('wrote ${target.path}');
      }
    }
    if (differs > 0) exit(1);
    if (check) stdout.writeln('all ${cases.length} goldens match DSS $version');
  } finally {
    work.deleteSync(recursive: true);
  }
}
