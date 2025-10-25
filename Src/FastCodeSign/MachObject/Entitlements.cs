using System.Formats.Asn1;
using System.Text;
using System.Xml;
using Genbox.FastCodeSign.Internal.MachObject.Headers.Enums;

namespace Genbox.FastCodeSign.MachObject;

public class Entitlements
{
    private readonly Dictionary<string, object> _values = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);

    public bool Contains(string identifier) => _values.ContainsKey(identifier);

    public void Add(string identifier, object value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(identifier);
        ArgumentNullException.ThrowIfNull(value);

        if (value is not (bool or string or string[]))
            throw new ArgumentException("Invalid entitlement value type: " + value.GetType().Name);

        _values.Add(identifier, value);
    }

    public void Remove(string identifier) => _values.Remove(identifier);

    public byte[] EncodeAsXml()
    {
        if (_values.Count == 0)
            return [];

        using MemoryStream ms = new MemoryStream();
        using XmlWriter writer = XmlWriter.Create(ms, new XmlWriterSettings
        {
            Indent = true,
            IndentChars = "  ",
            Encoding = new UTF8Encoding(false)
        });

        writer.WriteStartDocument(); // <?xml version="1.0" encoding="UTF-8"?>
        writer.WriteDocType(
            name: "plist",
            pubid: "-//Apple//DTD PLIST 1.0//EN",
            sysid: "http://www.apple.com/DTDs/PropertyList-1.0.dtd",
            subset: null
        );

        writer.WriteStartElement("plist");
        writer.WriteAttributeString("version", "1.0");

        writer.WriteStartElement("dict");

        foreach (KeyValuePair<string, object> pair in _values)
        {
            writer.WriteElementString("key", pair.Key.ToLowerInvariant());

            switch (pair.Value)
            {
                case string strVal:
                    writer.WriteElementString("string", strVal);
                    break;
                case bool boolVal:
                    writer.WriteStartElement(boolVal ? "true" : "false");
                    writer.WriteEndElement();
                    break;
                case string[] strArrVal:
                    writer.WriteStartElement("array");

                    foreach (string str in strArrVal)
                        writer.WriteElementString("string", str);

                    writer.WriteEndElement();
                    break;
                default:
                    throw new InvalidOperationException("Unsupported entitlement type: " + pair.Value.GetType().Name);
            }
        }

        writer.WriteEndElement(); // </dict>
        writer.WriteEndElement(); // </plist>
        writer.WriteEndDocument();

        Span<byte> xmlBytes = ms.GetBuffer().AsSpan(0, (int)ms.Length);

        byte[] buffer = new byte[8 + xmlBytes.Length];
        WriteUInt32BigEndian(buffer, (uint)CsMagic.Entitlements);
        WriteUInt32BigEndian(buffer[4..], (uint)buffer.Length);
        xmlBytes.CopyTo(buffer.AsSpan(8, xmlBytes.Length));

        return buffer;
    }

    public byte[] EncodeAsDer()
    {
        if (_values.Count == 0)
            return [];

        AsnWriter writer = new AsnWriter(AsnEncodingRules.DER);

        using (writer.PushSetOf())
        {
            foreach (KeyValuePair<string, object> pair in _values)
            {
                using (writer.PushSequence())
                {
                    writer.WriteCharacterString(UniversalTagNumber.UTF8String, pair.Key);

                    switch (pair.Value)
                    {
                        case int number:
                            writer.WriteInteger(number);
                            break;
                        case string str:
                            writer.WriteCharacterString(UniversalTagNumber.UTF8String, str);
                            break;
                        case string[] array:
                            using (writer.PushSequence())
                            {
                                foreach (string item in array)
                                    writer.WriteCharacterString(UniversalTagNumber.UTF8String, item);
                            }
                            break;
                        case bool boolean:
                            writer.WriteBoolean(boolean);
                            break;
                        default:
                            throw new InvalidOperationException("Unsupported entitlement type: " + pair.Value.GetType().Name);
                    }
                }
            }
        }

        byte[] asn1Bytes = writer.Encode();

        byte[] buffer = new byte[8 + asn1Bytes.Length];
        WriteUInt32BigEndian(buffer, (uint)CsMagic.EntitlementsDer);
        WriteUInt32BigEndian(buffer[4..], (uint)asn1Bytes.Length);
        asn1Bytes.CopyTo(buffer.AsSpan(8, asn1Bytes.Length));

        return asn1Bytes;
    }
}