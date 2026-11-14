package oracle;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlXCV;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.simplereport.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * Thin DSS oracle CLI. Input: a TSV manifest, one case per line:
 * id TAB signaturePath TAB contentPath-or-"-" TAB trustAnchorPath TAB validationTimeIso TAB poolPaths (comma list or "-") TAB policy ("default" or "no-revocation", files in /app/policy).
 * Output: one normalized JSON file per case at outDir/id.json (format documented in tool/dss_oracle/README.md).
 * Offline: no data loaders, no AIA, no revocation sources, no trusted lists. Default DSS validation policy.
 */
public final class Oracle {
  static String dssVersion = "unknown";

  public static void main(String[] args) throws Exception {
    if (args.length != 3) {
      System.err.println("usage: Oracle <manifest.tsv> <baseDir> <outDir>");
      System.exit(2);
    }
    Path v = Path.of("/app/dss_version.txt");
    if (Files.exists(v)) dssVersion = Files.readString(v).trim();
    Path baseDir = Path.of(args[1]);
    Path outDir = Path.of(args[2]);
    Files.createDirectories(outDir);
    for (String line : Files.readAllLines(Path.of(args[0]), StandardCharsets.UTF_8)) {
      if (line.isBlank()) continue;
      String[] f = line.split("\t", -1);
      String json;
      try {
        json = run(baseDir, f);
      } catch (Throwable t) {
        t.printStackTrace();
        json = "{\n  \"dssVersion\": " + q(dssVersion) + ",\n  \"validationTime\": " + q(f[4])
            + ",\n  \"error\": " + q(t.getClass().getName() + ": " + t.getMessage())
            + ",\n  \"signatures\": []\n}\n";
      }
      Files.writeString(outDir.resolve(f[0] + ".json"), json, StandardCharsets.UTF_8);
    }
  }

  static String run(Path base, String[] f) throws Exception {
    DSSDocument sig = new FileDocument(base.resolve(f[1]).toFile());
    CertificateVerifier verifier = new CommonCertificateVerifier();
    CommonTrustedCertificateSource trusted = new CommonTrustedCertificateSource();
    trusted.addCertificate(DSSUtils.loadCertificate(base.resolve(f[3]).toFile()));
    verifier.setTrustedCertSources(trusted);
    if (f.length > 5 && !f[5].equals("-") && !f[5].isEmpty()) {
      CommonCertificateSource pool = new CommonCertificateSource();
      for (String p : f[5].split(",")) pool.addCertificate(DSSUtils.loadCertificate(base.resolve(p).toFile()));
      verifier.setAdjunctCertSources(pool);
    }
    SignedDocumentValidator v = SignedDocumentValidator.fromDocument(sig);
    v.setCertificateVerifier(verifier);
    v.setValidationTime(Date.from(Instant.parse(f[4])));
    if (!f[2].equals("-")) {
      v.setDetachedContents(List.of(new FileDocument(base.resolve(f[2]).toFile())));
    }
    String policy = f.length > 6 && !f[6].isEmpty() ? f[6] : "default";
    Reports reports;
    try (var in = Files.newInputStream(Path.of("/app/policy/" + policy + ".xml"))) {
      reports = v.validateDocument(in);
    }
    SimpleReport sr = reports.getSimpleReport();
    DetailedReport dr = reports.getDetailedReport();

    StringBuilder sb = new StringBuilder();
    sb.append("{\n");
    sb.append("  \"dssVersion\": ").append(q(dssVersion)).append(",\n");
    sb.append("  \"validationTime\": ").append(q(f[4])).append(",\n");
    sb.append("  \"policy\": ").append(q(policy)).append(",\n");
    sb.append("  \"signatures\": [");
    int i = 0;
    for (String sid : sr.getSignatureIdList()) {
      sb.append(i == 0 ? "\n" : ",\n");
      sb.append("    {\n");
      sb.append("      \"index\": ").append(i).append(",\n");
      sb.append("      \"indication\": ").append(q(indication(sr.getIndication(sid)))).append(",\n");
      sb.append("      \"subIndication\": ").append(q(name(sr.getSubIndication(sid)))).append(",\n");
      Date st = sr.getSigningTime(sid);
      sb.append("      \"signingTime\": ").append(st == null ? "null" : q(Instant.ofEpochMilli(st.getTime()).toString())).append(",\n");
      sb.append("      \"scope\": [");
      List<XmlSignatureScope> scopes = sr.getSignatureScopes(sid);
      for (int k = 0; scopes != null && k < scopes.size(); k++) {
        sb.append(k == 0 ? "" : ", ").append("{\"kind\": ").append(q(scopes.get(k).getScope().name()))
            .append(", \"name\": ").append(q(scopes.get(k).getName())).append("}");
      }
      sb.append("],\n");
      sb.append("      \"blocks\": {");
      XmlBasicBuildingBlocks bbb = dr.getBasicBuildingBlockById(sid);
      List<String> blocks = new ArrayList<>();
      if (bbb != null) {
        add(blocks, "FC", bbb.getFC());
        add(blocks, "ISC", bbb.getISC());
        add(blocks, "VCI", bbb.getVCI());
        add(blocks, "XCV", bbb.getXCV());
        add(blocks, "CV", bbb.getCV());
        add(blocks, "SAV", bbb.getSAV());
      }
      sb.append(blocks.isEmpty() ? "" : "\n        ").append(String.join(",\n        ", blocks));
      sb.append(blocks.isEmpty() ? "}\n" : "\n      }\n");
      sb.append("    }");
      i++;
    }
    sb.append(i == 0 ? "]\n" : "\n  ]\n").append("}\n");
    return sb.toString();
  }

  static void add(List<String> out, String key, XmlConstraintsConclusion c) {
    if (c == null) return;
    XmlConclusion con = c.getConclusion();
    StringBuilder sb = new StringBuilder();
    sb.append(q(key)).append(": {\"indication\": ").append(q(con == null ? null : indication(con.getIndication())))
        .append(", \"subIndication\": ").append(q(con == null ? null : name(con.getSubIndication())))
        .append(", \"constraints\": [");
    int k = 0;
    for (var cons : c.getConstraint()) {
      sb.append(k++ == 0 ? "" : ", ").append("{\"name\": ")
          .append(q(cons.getName() == null ? null : cons.getName().getKey()))
          .append(", \"status\": ").append(q(cons.getStatus() == null ? null : cons.getStatus().name())).append("}");
    }
    sb.append("]");
    if (c instanceof XmlXCV xcv) {
      // Informational only (never compared): per-certificate results behind the XCV verdict.
      sb.append(", \"subXCV\": [");
      int s = 0;
      for (XmlSubXCV sub : xcv.getSubXCV()) {
        XmlConclusion sc = sub.getConclusion();
        sb.append(s++ == 0 ? "" : ", ").append("{\"certificate\": ").append(q(sub.getId()))
            .append(", \"trustAnchor\": ").append(sub.isTrustAnchor())
            .append(", \"indication\": ").append(q(sc == null ? null : indication(sc.getIndication())))
            .append(", \"subIndication\": ").append(q(sc == null ? null : name(sc.getSubIndication())))
            .append(", \"constraints\": [");
        int k2 = 0;
        for (var cons : sub.getConstraint()) {
          sb.append(k2++ == 0 ? "" : ", ").append("{\"name\": ")
              .append(q(cons.getName() == null ? null : cons.getName().getKey()))
              .append(", \"status\": ").append(q(cons.getStatus() == null ? null : cons.getStatus().name())).append("}");
        }
        sb.append("]}");
      }
      sb.append("]");
    }
    sb.append("}");
    out.add(sb.toString());
  }

  static String name(Enum<?> e) { return e == null ? null : e.name(); }

  /** DSS enum names use underscores (TOTAL_PASSED); ETSI spells them with hyphens. */
  static String indication(Enum<?> e) { return e == null ? null : e.name().replace('_', '-'); }

  static String q(String s) {
    if (s == null) return "null";
    StringBuilder b = new StringBuilder("\"");
    for (char ch : s.toCharArray()) {
      switch (ch) {
        case '"' -> b.append("\\\"");
        case '\\' -> b.append("\\\\");
        case '\n' -> b.append("\\n");
        case '\r' -> b.append("\\r");
        case '\t' -> b.append("\\t");
        default -> {
          if (ch < 0x20) b.append(String.format("\\u%04x", (int) ch));
          else b.append(ch);
        }
      }
    }
    return b.append('"').toString();
  }
}
