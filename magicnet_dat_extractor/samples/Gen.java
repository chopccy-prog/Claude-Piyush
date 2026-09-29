import java.io.*;
import java.util.*;

public class Gen {
    enum Mode { AUTO, PPM, PERCENT }
    static class Peak implements Serializable {
        private static final long serialVersionUID = 42L;
        String name; double area; double conc; int num; boolean flag; Mode mode; double[] curve; Date when;
        Peak(String n, double a, double c, int i, Mode m) { name = n; area = a; conc = c; num = i; flag = i % 2 == 0; mode = m; curve = new double[]{1.5, 2.5, i}; when = new Date(1735689600000L + i * 1000L); }
    }
    static class Sample extends Peak {
        private static final long serialVersionUID = 7L;
        String ident; List<Peak> peaks = new ArrayList<>(); Map<String, Object> props = new HashMap<>(); Object nothing = null; Integer boxed = 17;
        transient int skipped = 99;
        Sample(String id) { super("base", 0.1, 0.2, 3, Mode.AUTO); ident = id; }
        private void writeObject(ObjectOutputStream o) throws IOException { o.defaultWriteObject(); o.writeInt(1234); o.writeUTF("custom"); o.writeObject(Mode.PERCENT); }
        private void readObject(ObjectInputStream i) throws IOException, ClassNotFoundException { i.defaultReadObject(); i.readInt(); i.readUTF(); i.readObject(); }
    }
    public static void main(String[] a) throws Exception {
        Sample s = new Sample("SMP-001");
        s.peaks.add(new Peak("Chloride", 12.5, 0.75, 1, Mode.PPM));
        s.peaks.add(new Peak("Sulfate", 30.25, 1.5, 2, Mode.PERCENT));
        s.peaks.add(s.peaks.get(0));          // back-reference
        s.props.put("method", "PHOSPHATE BINDING CAPACITY");
        s.props.put("count", 3);
        s.props.put("mode", Mode.AUTO);
        s.props.put("date", new Date(1700000000000L));
        try (ObjectOutputStream o = new ObjectOutputStream(new FileOutputStream("sample.ser"))) {
            o.writeObject(s);
            o.writeObject(Mode.PPM);
            o.writeObject("second");
            o.writeObject(new int[]{1, 2, 3});
            o.writeObject(new String[]{"x", "y"});
            o.writeObject(new java.math.BigDecimal("123.456"));
        }
        // a second file: just an enum, as MagIC Net seems to store many of them
        try (ObjectOutputStream o = new ObjectOutputStream(new FileOutputStream("enum.ser"))) { o.writeObject(Mode.PERCENT); }
    }
}
