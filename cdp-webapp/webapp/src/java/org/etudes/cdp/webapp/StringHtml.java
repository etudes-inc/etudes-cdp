/**********************************************************************************
 * $URL: https://source.etudes.org/svn/e3/cdp/trunk/cdp-webapp/webapp/src/java/org/etudes/cdp/webapp/StringHtml.java $
 * $Id: StringHtml.java 7136 2014-01-15 20:03:04Z ggolden $
 ***********************************************************************************
 *
 * Copyright (c) 2011, 2012, 2013, 2014 Etudes, Inc.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 **********************************************************************************/

package org.etudes.cdp.webapp;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.sakaiproject.util.StringUtil;

public class StringHtml
{
	/** Our log. */
	private static Log M_log = LogFactory.getLog(StringHtml.class);

	// Note: see here for BBCode: http://www.bbcode.org/reference.php

	/** Our log. */
	// private static Log M_log = LogFactory.getLog(StringHtml.class);

	// Warning: do NOT use actual funky characters in this source - no "yen" characters, etc. They may look ok while editing, but they go through
	// way too many character-set sensitive transitions before they get built on a production app server - and will not survive the journey.
	// use the unicode escape sequence instead.
	protected static String htmlEntities[] =
	{
			// Note: nbsp is first so we can skip in in stringHtmlFromPlain; amp is left out, treated specially
			"&nbsp;", "&#160;", "\u0020", // space
			"&lt;", "&#60;", "\u003C", // lt
			"&gt;", "&#62;", "\u003C", // gt
			"&cent;", "&#162;", "\u00A2", // cent
			"&pound;", "&#163;", "\u00A3", // pound
			"&yen;", "&#165;", "\u00A5", // yen
			"&euro;", "&#8364;", "\u20AC", // euro
			"&sect;", "&#167;", "\u00A7", // section
			"&copy;", "&#169;", "\u00A9", // copyright
			"&reg;", "&#174;", "\u00AE", // registered trademark
			"&trade;", "&#8482;", "\u2122", // trademark
			"&bull;", "&#8226;", "\u2022", // bullet
			"&quot;", "&#34;", "\"", // "\u0022", quote

			"&apos;", "&#39;", "\u0027", // APOSTROPHE
			"&iexcl;", "&#161;", "\u00A1", // INVERTED EXCLAMATION MARK
			"&curren;", "&#164;", "\u00A4", // CURRENCY SIGN
			"&brvbar;", "&#166;", "\u00A6", // BROKEN BAR
			"&uml;", "&#168;", "\u00A8", // DIAERESIS
			"&ordf;", "&#170;", "\u00AA", // FEMININE ORDINAL INDICATOR
			"&laquo;", "&#171;", "\u00AB", // LEFT-POINTING DOUBLE ANGLE QUOTATION MARK
			"&not;", "&#172;", "\u00AC", // NOT SIGN
			"&shy;", "&#173;", "\u00AD", // SOFT HYPHEN
			"&macr;", "&#175;", "\u00AF", // MACRON
			"&deg;", "&#176;", "\u00B0", // DEGREE SIGN
			"&plusmn;", "&#177;", "\u00B1", // PLUS-MINUS SIGN
			"&sup2;", "&#178;", "\u00B2", // SUPERSCRIPT TWO
			"&sup3;", "&#179;", "\u00B3", // SUPERSCRIPT THREE
			"&acute;", "&#180;", "\u00B4", // ACUTE ACCENT
			"&micro;", "&#181;", "\u00B5", // MICRO SIGN
			"&para;", "&#182;", "\u00B6", // PILCROW SIGN
			"&middot;", "&#183;", "\u00B7", // MIDDLE DOT
			"&cedil;", "&#184;", "\u00B8", // CEDILLA
			"&sup1;", "&#185;", "\u00B9", // SUPERSCRIPT ONE
			"&ordm;", "&#186;", "\u00BA", // MASCULINE ORDINAL INDICATOR
			"&raquo;", "&#187;", "\u00BB", // RIGHT-POINTING DOUBLE ANGLE QUOTATION MARK
			"&frac14;", "&#188;", "\u00BC", // VULGAR FRACTION ONE QUARTER
			"&frac12;", "&#189;", "\u00BD", // VULGAR FRACTION ONE HALF
			"&frac34;", "&#190;", "\u00BE", // VULGAR FRACTION THREE QUARTERS
			"&iquest;", "&#191;", "\u00BF", // INVERTED QUESTION MARK
			"&times;", "&#215;", "\u00D7", // MULTIPLICATION SIGN
			"&divide;", "&#247;", "\u00F7", // DIVISION SIGN

			"&Agrave;", "&#192;", "\u00C0", // "capital a, grave accent"
			"&Aacute;", "&#193;", "\u00C1", // "capital a, acute accent"
			"&Acirc;", "&#194;", "\u00C2", // "capital a, circumflex accent"
			"&Atilde;", "&#195;", "\u00C3", // "capital a, tilde"
			"&Auml;", "&#196;", "\u00C4", // "capital a, umlaut mark"
			"&Aring;", "&#197;", "\u00C5", // "capital a, ring"
			"&AElig;", "&#198;", "\u00C6", // capital ae
			"&Ccedil;", "&#199;", "\u00C7", // "capital c, cedilla"
			"&Egrave;", "&#200;", "\u00C8", // "capital e, grave accent"
			"&Eacute;", "&#201;", "\u00C9", // "capital e, acute accent"
			"&Ecirc;", "&#202;", "\u00CA", // "capital e, circumflex accent"
			"&Euml;", "&#203;", "\u00CB", // ""capital e, umlaut mark"
			"&Igrave;", "&#204;", "\u00CC", // ""capital i, grave accent"
			"&Iacute;", "&#205;", "\u00CD", // ""capital i, acute accent"
			"&Icirc;", "&#206;", "\u00CE", // ""capital i, circumflex accent"
			"&Iuml;", "&#207;", "\u00CF", // ""capital i, umlaut mark"
			"&ETH;", "&#208;", "\u00D0", // ""capital eth, Icelandic"
			"&Ntilde;", "&#209;", "\u00D1", // ""capital n, tilde"
			"&Ograve;", "&#210;", "\u00D2", // ""capital o, grave accent"
			"&Oacute;", "&#211;", "\u00D3", // ""capital o, acute accent"
			"&Ocirc;", "&#212;", "\u00D4", // ""capital o, circumflex accent"
			"&Otilde;", "&#213;", "\u00D5", // ""capital o, tilde"
			"&Ouml;", "&#214;", "\u00D6", // "capital o, umlaut mark"
			"&Oslash;", "&#216;", "\u00D8", // "capital o, slash"
			"&Ugrave;", "&#217;", "\u00D9", // "capital u, grave accent"
			"&Uacute;", "&#218;", "\u00DA", // "capital u, acute accent"
			"&Ucirc;", "&#219;", "\u00DB", // "capital u, circumflex accent"
			"&Uuml;", "&#220;", "\u00DC", // "capital u, umlaut mark"
			"&Yacute;", "&#221;", "\u00DD", // "capital y, acute accent"
			"&THORN;", "&#222;", "\u00DE", // "capital THORN, Icelandic"
			"&szlig;", "&#223;", "\u00DF", // "small sharp s, German"
			"&agrave;", "&#224;", "\u00E0", // "small a, grave accent"
			"&aacute;", "&#225;", "\u00E1", // "small a, acute accent"
			"&acirc;", "&#226;", "\u00E2", // "small a, circumflex accent"
			"&atilde;", "&#227;", "\u00E3", // "small a, tilde"
			"&auml;", "&#228;", "\u00E4", // "small a, umlaut mark"
			"&aring;", "&#229;", "\u00E5", // "small a, ring"
			"&aelig;", "&#230;", "\u00E6", // small ae
			"&ccedil;", "&#231;", "\u00E7", // "small c, cedilla"
			"&egrave;", "&#232;", "\u00E8", // "small e, grave accent"
			"&eacute;", "&#233;", "\u00E9", // "small e, acute accent"
			"&ecirc;", "&#234;", "\u00EA", // "small e, circumflex accent"
			"&euml;", "&#235;", "\u00EB", // "small e, umlaut mark"
			"&igrave;", "&#236;", "\u00EC", // "small i, grave accent"
			"&iacute;", "&#237;", "\u00ED", // "small i, acute accent"
			"&icirc;", "&#238;", "\u00EE", // "small i, circumflex accent"
			"&iuml;", "&#239;", "\u00EF", // "small i, umlaut mark"
			"&eth;", "&#240;", "\u00F0", // "small eth, Icelandic"
			"&ntilde;", "&#241;", "\u00F1", // "small n, tilde"
			"&ograve;", "&#242;", "\u00F2", // "small o, grave accent"
			"&oacute;", "&#243;", "\u00F3", // "small o, acute accent"
			"&ocirc;", "&#244;", "\u00F4", // "small o, circumflex accent"
			"&otilde;", "&#245;", "\u00F5", // "small o, tilde"
			"&ouml;", "&#246;", "\u00F6", // "small o, umlaut mark"
			"&oslash;", "&#248;", "\u00F8", // "small o, slash"
			"&ugrave;", "&#249;", "\u00F9", // "small u, grave accent"
			"&uacute;", "&#250;", "\u00FA", // "small u, acute accent"
			"&ucirc;", "&#251;", "\u00FB", // "small u, circumflex accent"
			"&uuml;", "&#252;", "\u00FC", // "small u, umlaut mark"
			"&yacute;", "&#253;", "\u00FD", // "small y, acute accent"
			"&thorn;", "&#254;", "\u00FE", // "small thorn, Icelandic"
			"&yuml;", "&#255;", "\u00FF", // "small y, umlaut mark"

			"&forall;", "&#8704;", "\u2200", // for all
			"&part;", "&#8706;", "\u2202", // part
			"&exist;", "&#8707;", "\u2203", // exists
			"&empty;", "&#8709;", "\u2205", // empty
			"&nabla;", "&#8711;", "\u2207", // nabla
			"&isin;", "&#8712;", "\u2208", // isin
			"&notin;", "&#8713;", "\u2209", // notin
			"&ni;", "&#8715;", "\u220B", // ni
			"&prod;", "&#8719;", "\u220F", // prod
			"&sum;", "&#8721;", "\u2211", // sum
			"&minus;", "&#8722;", "\u2212", // minus
			"&lowast;", "&#8727;", "\u2217", // lowast
			"&radic;", "&#8730;", "\u221A", // square root
			"&prop;", "&#8733;", "\u221D", // proportional to
			"&infin;", "&#8734;", "\u221E", // infinity
			"&ang;", "&#8736;", "\u2220", // angle
			"&and;", "&#8743;", "\u2227", // and
			"&or;", "&#8744;", "\u2228", // or
			"&cap;", "&#8745;", "\u2229", // cap
			"&cup;", "&#8746;", "\u222A", // cup
			"&int;", "&#8747;", "\u222B", // integral
			"&there4;", "&#8756;", "\u2234", // therefore
			"&sim;", "&#8764;", "\u223C", // similar to
			"&cong;", "&#8773;", "\u2245", // congruent to
			"&asymp;", "&#8776;", "\u2248", // almost equal
			"&ne;", "&#8800;", "\u2260", // not equal
			"&equiv;", "&#8801;", "\u2261", // equivalent
			"&le;", "&#8804;", "\u2264", // less or equal
			"&ge;", "&#8805;", "\u2265", // greater or equal
			"&sub;", "&#8834;", "\u2282", // subset of
			"&sup;", "&#8835;", "\u2283", // superset of
			"&nsub;", "&#8836;", "\u2284", // not subset of
			"&sube;", "&#8838;", "\u2286", // subset or equal
			"&supe;", "&#8839;", "\u2287", // superset or equal
			"&oplus;", "&#8853;", "\u2295", // circled plus
			"&otimes;", "&#8855;", "\u2297", // circled times
			"&perp;", "&#8869;", "\u22A5", // perpendicular
			"&sdot;", "&#8901;", "\u22C5", // dot operator

			"&Alpha;", "&#913;", "\u0391", // Alpha
			"&Beta;", "&#914;", "\u0392", // Beta
			"&Gamma;", "&#915;", "\u0393", // Gamma
			"&Delta;", "&#916;", "\u0394", // Delta
			"&Epsilon;", "&#917;", "\u0395", // Epsilon
			"&Zeta;", "&#918;", "\u0396", // Zeta
			"&Eta;", "&#919;", "\u0397", // Eta
			"&Theta;", "&#920;", "\u0398", // Theta
			"&Iota;", "&#921;", "\u0399", // Iota
			"&Kappa;", "&#922;", "\u039A", // Kappa
			"&Lambda;", "&#923;", "\u039B", // Lambda
			"&Mu;", "&#924;", "\u039C", // Mu
			"&Nu;", "&#925;", "\u039D", // Nu
			"&Xi;", "&#926;", "\u039E", // Xi
			"&Omicron;", "&#927;", "\u039F", // Omicron
			"&Pi;", "&#928;", "\u03A0", // Pi
			"&Rho;", "&#929;", "\u03A1", // Rho
			"&Sigma;", "&#931;", "\u03A3", // Sigma
			"&Tau;", "&#932;", "\u03A4", // Tau
			"&Upsilon;", "&#933;", "\u03A5", // Upsilon
			"&Phi;", "&#934;", "\u03A6", // Phi
			"&Chi;", "&#935;", "\u03A7", // Chi
			"&Psi;", "&#936;", "\u03A8", // Psi
			"&Omega;", "&#937;", "\u03A9", // Omega
			"&alpha;", "&#945;", "\u03B1", // alpha
			"&beta;", "&#946;", "\u03B2", // beta
			"&gamma;", "&#947;", "\u03B3", // gamma
			"&delta;", "&#948;", "\u03B4", // delta
			"&epsilon;", "&#949;", "\u03B5", // epsilon
			"&zeta;", "&#950;", "\u03B6", // zeta
			"&eta;", "&#951;", "\u03B7", // eta
			"&theta;", "&#952;", "\u03B8", // theta
			"&iota;", "&#953;", "\u03B9", // iota
			"&kappa;", "&#954;", "\u03BA", // kappa
			"&lambda;", "&#955;", "\u03BB", // lambda
			"&mu;", "&#956;", "\u03BC", // mu
			"&nu;", "&#957;", "\u03BD", // nu
			"&xi;", "&#958;", "\u03BE", // xi
			"&omicron;", "&#959;", "\u03BF", // omicron
			"&pi;", "&#960;", "\u03C0", // pi
			"&rho;", "&#961;", "\u03C1", // rho
			"&sigmaf;", "&#962;", "\u03C2", // sigmaf
			"&sigma;", "&#963;", "\u03C3", // sigma
			"&tau;", "&#964;", "\u03C4", // tau
			"&upsilon;", "&#965;", "\u03C5", // upsilon
			"&phi;", "&#966;", "\u03C6", // phi
			"&chi;", "&#967;", "\u03C7", // chi
			"&psi;", "&#968;", "\u03C8", // psi
			"&omega;", "&#969;", "\u03C9", // omega
			"&thetasym;", "&#977;", "\u03D1", // theta symbol
			"&upsih;", "&#978;", "\u03D2", // upsilon symbol
			"&piv;", "&#982;", "\u03D6", // pi symbol

			"&OElig;", "&#338;", "\u0152", // capital ligature OE
			"&oelig;", "&#339;", "\u0153", // small ligature oe
			"&Scaron;", "&#352;", "\u0160", // capital S with caron
			"&scaron;", "&#353;", "\u0161", // small S with caron
			"&Yuml;", "&#376;", "\u0178", // capital Y with diaeres
			"&fnof;", "&#402;", "\u0192", // f with hook
			"&circ;", "&#710;", "\u02C6", // modifier letter circumflex accent
			"&tilde;", "&#732;", "\u02DC", // small tilde
			"&ensp;", "&#8194;", "\u2002", // en space
			"&emsp;", "&#8195;", "\u2003", // em space
			"&thinsp;", "&#8201;", "\u2009", // thin space
			"&zwnj;", "&#8204;", "\u200C", // zero width non-joiner
			"&zwj;", "&#8205;", "\u200D", // zero width joiner
			"&lrm;", "&#8206;", "\u200E", // left-to-right mark
			"&rlm;", "&#8207;", "\u200F", // right-to-left mark
			"&ndash;", "&#8211;", "\u2013", // en dash
			"&mdash;", "&#8212;", "\u2014", // em dash
			"&lsquo;", "&#8216;", "\u2018", // left single quotation mark
			"&rsquo;", "&#8217;", "\u2019", // right single quotation mark
			"&sbquo;", "&#8218;", "\u201A", // single low-9 quotation mark
			"&ldquo;", "&#8220;", "\u201C", // left double quotation mark
			"&rdquo;", "&#8221;", "\u201D", // right double quotation mark
			"&bdquo;", "&#8222;", "\u201E", // double low-9 quotation mark
			"&dagger;", "&#8224;", "\u2020", // dagger
			"&Dagger;", "&#8225;", "\u2021", // double dagger
			"&hellip;", "&#8230;", "\u2026", // horizontal ellipsis
			"&permil;", "&#8240;", "\u2030", // per mille
			"&prime;", "&#8242;", "\u2032", // minutes
			"&Prime;", "&#8243;", "\u2033", // seconds
			"&lsaquo;", "&#8249;", "\u2039", // single left angle quotation
			"&rsaquo;", "&#8250;", "\u203A", // single right angle quotation
			"&oline;", "&#8254;", "\u203E", // overline
			"&larr;", "&#8592;", "\u2190", // left arrow
			"&uarr;", "&#8593;", "\u2191", // up arrow
			"&rarr;", "&#8594;", "\u2192", // right arrow
			"&darr;", "&#8595;", "\u2193", // down arrow
			"&harr;", "&#8596;", "\u2194", // left right arrow
			"&crarr;", "&#8629;", "\u2185", // carriage return arrow
			"&lceil;", "&#8968;", "\u2308", // left ceiling
			"&rceil;", "&#8969;", "\u2309", // right ceiling
			"&lfloor;", "&#8970;", "\u230A", // left floor
			"&rfloor;", "&#8971;", "\u230B", // right floor
			"&loz;", "&#9674;", "\u25CA", // lozenge
			"&spades;", "&#9824;", "\u2660", // spade
			"&clubs;", "&#9827;", "\u2663", // club
			"&hearts;", "&#9829;", "\u2665", // heart
			"&diams;", "&#9830;", "\u2666", // diamond

			null };

	public static String htmlFromBbCode(String plain)
	{
		try
		{
			// images
			plain = imageToHtml(plain);

			// emoticons
			plain = emotToHtml(plain);

			// links
			plain = linkToHtml(plain);

			// bold
			plain = boldToHtml(plain);

			// italic
			plain = italicToHtml(plain);

			// underline
			plain = underlineToHtml(plain);

			// strike
			plain = strikeToHtml(plain);

			// font
			plain = fontToHtml(plain);

			// center
			plain = centerToHtml(plain);

			// youtube
			plain = youtubeToHtml(plain);
		}
		catch (Exception e)
		{
			M_log.warn("htmlFromBbCode: " + e.toString() + "\n" + plain + "\n");
		}

		return plain;
	}

	// return the string with plain text characters converted into html as needed.
	public static String htmlFromPlain(String plain)
	{
		// do &amp; first, so we don't recognize "&" we just put in there as part of entities
		Pattern p = Pattern.compile("&", Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE | Pattern.DOTALL);
		Matcher m = p.matcher(plain);
		plain = m.replaceAll("&amp;");

		// convert all entities - skip the first (&nbsp;)
		int i = 3;
		while (htmlEntities[i] != null)
		{
			// take two of the three values
			String namedEntity = htmlEntities[i++];
			String numericEntity = htmlEntities[i++];
			String character = htmlEntities[i++];

			// replace the character with the named entity (e1)
			// (except for &apos;, which we replace with the numeric, because it is valid XML but not valid HTML)
			if (namedEntity.equals("&apos;")) namedEntity = numericEntity;
			// [buf replaceOccurrencesOfString:character withString:namedEntity options:0 range:NSMakeRange(0, [buf length])];
			p = Pattern.compile(character, Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE | Pattern.DOTALL);
			m = p.matcher(plain);
			plain = m.replaceAll(namedEntity);
		}

		plain = htmlFromBbCode(plain);

		// convert new lines to <br />
		// [buf replaceOccurrencesOfString:@"\n" withString:@"<br />" options:0 range:NSMakeRange(0, [buf length])];
		p = Pattern.compile("\\n", Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE | Pattern.DOTALL);
		m = p.matcher(plain);
		plain = m.replaceAll("<br />");

		// convert any multiple white space into &nbsp; (leave single spaces as spaces)

		return plain;
	}

	public static String htmlFromQuote(String quote)
	{
		try
		{
			boolean hit = false;
			Pattern p = Pattern.compile("\\[quote\\s*=\\s*(.*?)\\](.*?)\\[/quote\\]", Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE
					| Pattern.DOTALL);
			int pass = 0;
			while (true)
			{
				Matcher m = p.matcher(quote);
				String replaced = m.replaceAll("<div class=\"ETquote\">$1 wrote:<div class=\"ETquoted\">$2</div></div>");
				boolean changed = !replaced.equals(quote);
				quote = replaced;
				if (!changed) break;
				pass++;
				if (pass == 100) break;
			}
			if (pass > 0) hit = true;

			p = Pattern.compile("\\[quote\\](.*?)\\[/quote\\]", Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE | Pattern.DOTALL);
			pass = 0;
			while (true)
			{
				Matcher m = p.matcher(quote);
				String replaced = m.replaceAll("<div class=\"ETquote\"><div class=\"ETquoted\">$1</div></div>");
				boolean changed = !replaced.equals(quote);
				quote = replaced;
				if (!changed) break;
				pass++;
				if (pass == 100) break;
			}
			if (pass > 0) hit = true;

			// if we have any
			if (hit)
			{
				quote = "<style type=\"text/css\">.ETquote {font-weight:bold; font-family:sans-serif; font-size:small; width:80%; margin:0.5em 0px 0.5em 2em;}.ETquoted {font-weight:normal; background-color:#F3F5FF; border:1px solid #01336b; padding:0.25em 0em 0.25em 0.25em;}</style>"
						+ quote;
			}
		}
		catch (Exception e)
		{
			M_log.warn("htmlFromQuote: " + e.toString() + "\n" + quote + "\n");
		}

		return quote;
	}

	public static String plainFromHtml(String html)
	{
		// remove all new lines
		// [buf replaceOccurrencesOfString:@"\r\n" withString:@"" options:0 range:NSMakeRange(0, [buf length])];
		// [buf replaceOccurrencesOfString:@"\n" withString:@"" options:0 range:NSMakeRange(0, [buf length])];
		// [buf replaceOccurrencesOfString:@"\r" withString:@"" options:0 range:NSMakeRange(0, [buf length])];
		Pattern p = Pattern.compile("\\r\\n", Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE | Pattern.DOTALL);
		Matcher m = p.matcher(html);
		html = m.replaceAll("");

		p = Pattern.compile("\\n", Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE | Pattern.DOTALL);
		m = p.matcher(html);
		html = m.replaceAll("");

		p = Pattern.compile("\\r", Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE | Pattern.DOTALL);
		m = p.matcher(html);
		html = m.replaceAll("");

		// remove all tabs
		// [buf replaceOccurrencesOfString:@"\t" withString:@"" options:0 range:NSMakeRange(0, [buf length])];
		p = Pattern.compile("\\t", Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE | Pattern.DOTALL);
		m = p.matcher(html);
		html = m.replaceAll("");

		// remove all multiple white spaces
		// TODO:

		// convert all <br /> to new lines
		// [buf replaceOccurrencesOfString:@"<br />" withString:@"\n" options:0 range:NSMakeRange(0, [buf length])];
		// [buf replaceOccurrencesOfString:@"<br/>" withString:@"\n" options:0 range:NSMakeRange(0, [buf length])];
		p = Pattern.compile("<br\\s*/>", Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE | Pattern.DOTALL);
		m = p.matcher(html);
		html = m.replaceAll("\n");

		// convert links
		html = linkToPlain(html);

		// convert emoticons
		html = emotToPlain(html);

		// convert images
		html = imageToPlain(html);

		// bold
		html = boldToPlain(html);

		// italic
		html = italicToPlain(html);

		// underline
		html = underlineToPlain(html);

		// strike
		html = strikeToPlain(html);

		// font
		html = fontToPlain(html);

		// center
		html = centerToPlain(html);

		// youtube
		html = youtubeToPlain(html);

		// convert <p> and </p> to new lines
		html = pToPlain(html);

		// convert divs to new lines
		html = divToPlain(html);

		// convert lists
		html = listToPlain(html);
		html = liToPlain(html);
		html = dtToPlain(html);

		// drop all remaining tags
		html = tagsToPlain(html);

		// convert html all entities
		int i = 0;
		while (htmlEntities[i] != null)
		{
			// take the three values
			String e1 = htmlEntities[i++];
			String e2 = htmlEntities[i++];
			String replacement = htmlEntities[i++];

			// replace either entity with the character
			// [buf replaceOccurrencesOfString:e1 withString:replacement options:0 range:NSMakeRange(0, [buf length])];
			// [buf replaceOccurrencesOfString:e2 withString:replacement options:0 range:NSMakeRange(0, [buf length])];
			p = Pattern.compile(e1, Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE | Pattern.DOTALL);
			m = p.matcher(html);
			html = m.replaceAll(replacement);

			p = Pattern.compile(e2, Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE | Pattern.DOTALL);
			m = p.matcher(html);
			html = m.replaceAll(replacement);
		}

		// do &amp; last, so we don't accidently create an entity by putting in and then recognizing the "&" character
		// [buf replaceOccurrencesOfString:@"&amp;" withString:@"&" options:0 range:NSMakeRange(0, [buf length])];
		// [buf replaceOccurrencesOfString:@"&#38;" withString:@"&" options:0 range:NSMakeRange(0, [buf length])];
		p = Pattern.compile("&amp;", Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE | Pattern.DOTALL);
		m = p.matcher(html);
		html = m.replaceAll("&");

		p = Pattern.compile("&#38;", Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE | Pattern.DOTALL);
		m = p.matcher(html);
		html = m.replaceAll("&");

		return html;
	}

	/**
	 * Recognize BBCode [b] tags and render them in html.
	 * 
	 * @param plain
	 *        The text with the BBCode tags.
	 * @return The converted text.
	 */
	protected static String boldToHtml(String plain)
	{
		Pattern p = Pattern.compile("\\[b\\](.*?)\\[/b\\]", Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE | Pattern.DOTALL);
		Matcher m = p.matcher(plain);
		plain = m.replaceAll("<strong>$1</strong>");

		return plain;
	}

	/**
	 * Recognize strong and b tags in html, render it into bbcode [b]
	 * 
	 * @param html
	 * @return
	 */
	protected static String boldToPlain(String html)
	{
		Pattern p = Pattern.compile("<strong>(.*?)</strong>", Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE | Pattern.DOTALL);
		Matcher m = p.matcher(html);
		html = m.replaceAll("[b]$1[/b]");

		p = Pattern.compile("<b>(.*?)</b>", Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE | Pattern.DOTALL);
		m = p.matcher(html);
		html = m.replaceAll("[b]$1[/b]");

		return html;
	}

	/**
	 * Recognize html text centering, render as BBcode center tag.
	 * 
	 * @param html
	 * @return
	 */
	protected static String centerToHtml(String plain)
	{
		Pattern p = Pattern.compile("\\[center\\](.*?)\\[/center\\]", Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE | Pattern.DOTALL);
		Matcher m = p.matcher(plain);
		plain = m.replaceAll("<div align=\"center\">$1</div>");
		return plain;
	}

	/**
	 * Recognize html text centering, render as BBcode center tag.
	 * 
	 * @param html
	 * @return
	 */
	protected static String centerToPlain(String html)
	{
		Pattern p = Pattern.compile("<div align\\s*=\\s*\"center\">(.*?)</div>", Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE | Pattern.DOTALL);
		Matcher m = p.matcher(html);
		html = m.replaceAll("[center]$1[/center]");

		p = Pattern.compile("<p align\\s*=\\s*\"center\">(.*?)</p>", Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE | Pattern.DOTALL);
		m = p.matcher(html);
		html = m.replaceAll("[center]$1[/center]");

		return html;
	}

	protected static String divToPlain(String html)
	{
		// match <div> tags, collect the text within the tag, add a new line before and after
		Pattern p = Pattern.compile("<div.*?>(.*?)</div>", Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE | Pattern.DOTALL);
		Matcher m = p.matcher(html);
		html = m.replaceAll("\n$1\n");
		return html;
	}

	protected static String dtToPlain(String html)
	{
		// match <dt> tags, collect the text within the tag, add a dash, and new line before
		Pattern p = Pattern.compile("<dt.*?>(.*?)</dt>", Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE | Pattern.DOTALL);
		Matcher m = p.matcher(html);
		html = m.replaceAll("\n- $1");
		return html;
	}

	/**
	 * Recognize BBCode [emot] tags and render them in html.
	 * 
	 * @param plain
	 *        The text with the BBCode tags.
	 * @return The converted text.
	 */
	protected static String emotToHtml(String plain)
	{
		Pattern p = Pattern.compile("\\[emot\\](.*?)\\[/emot\\]", Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE | Pattern.DOTALL);
		Matcher m = p.matcher(plain);
		plain = m.replaceAll("<img src=\"/library/editor/FCKeditor/editor/images/smiley/msn/$1.gif\" alt=\"emoticon $1\" />");

		return plain;
	}

	/**
	 * Recognize emoticons, render it into (enhanced) bbcode [emot]
	 * 
	 * @param html
	 * @return
	 */
	protected static String emotToPlain(String html)
	{
		Pattern p = Pattern.compile("<img.*?src\\s*=\\s*\"/library/editor/FCKeditor/editor/images/smiley/msn/(.*?).gif\".*?/>",
				Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE | Pattern.DOTALL);
		Matcher m = p.matcher(html);
		html = m.replaceAll("[emot]$1[/emot]");

		return html;
	}

	/**
	 * Recognize BBCode [b] tags and render them in html.
	 * 
	 * @param plain
	 *        The text with the BBCode tags.
	 * @return The converted text.
	 */
	protected static String fontToHtml(String plain)
	{
		Pattern p = Pattern.compile("\\[size\\s*=\\s*(.*?)\\](.*?)\\[/size\\]", Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE | Pattern.DOTALL);
		Matcher m = p.matcher(plain);
		plain = m.replaceAll("<font size=\"$1\">$2</font>");

		p = Pattern.compile("\\[color\\s*=\\s*(.*?)\\](.*?)\\[/color\\]", Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE | Pattern.DOTALL);
		m = p.matcher(plain);
		plain = m.replaceAll("<font color=\"$1\">$2</font>");

		// collapse double fonts
		p = Pattern.compile("<font(.*?)><font(.*?)>(.*?)</font></font>", Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE | Pattern.DOTALL);
		m = p.matcher(plain);
		plain = m.replaceAll("<font$1$2>$3</font>");

		return plain;
	}

	/**
	 * Recognize html font tags, and render them in BBcode.
	 * 
	 * @param html
	 *        The text with html tags.
	 * @return The text with the tags replaced.
	 */
	protected static String fontToPlain(String html)
	{
		StringBuffer buf = new StringBuffer();

		Pattern pSize = Pattern.compile("size\\s*=\\s*\"(.*?)\"", Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE | Pattern.DOTALL);
		Pattern pColor = Pattern.compile("color\\s*=\\s*\"(.*?)\"", Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE | Pattern.DOTALL);
		Pattern p = Pattern.compile("<font(.*?)>(.*?)</font>", Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE | Pattern.DOTALL);
		Matcher m = p.matcher(html);
		while (m.find())
		{
			// look for attributes
			String size = null;
			String color = null;
			Matcher m2 = pSize.matcher(m.group(1));
			if (m2.find())
			{
				size = StringUtil.trimToNull(m2.group(1));
			}
			m2 = pColor.matcher(m.group());
			if (m2.find())
			{
				color = StringUtil.trimToNull(m2.group(1));
			}

			StringBuffer replacement = new StringBuffer();

			if (color != null)
			{
				replacement.append("[color=" + color + "]");
			}
			if (size != null)
			{
				replacement.append("[size=" + size + "]");
			}
			replacement.append(m.group(2));
			if (size != null)
			{
				replacement.append("[/size]");
			}
			if (color != null)
			{
				replacement.append("[/color]");
			}

			m.appendReplacement(buf, Matcher.quoteReplacement(replacement.toString()));
		}

		m.appendTail(buf);

		return buf.toString();
	}

	/**
	 * Recognize the BBCode [img] tag, and render it in html.
	 * 
	 * @param plain
	 *        The text containing the tags.
	 * @return The text with the tags rendered.
	 */
	protected static String imageToHtml(String plain)
	{
		StringBuffer buf = new StringBuffer();

		Pattern pWidth = Pattern.compile("width\\s*=\\s*&quot;(.*?)&quot;", Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE | Pattern.DOTALL);
		Pattern pHeight = Pattern.compile("height\\s*=\\s*&quot;(.*?)&quot;", Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE | Pattern.DOTALL);
		Pattern pAlt = Pattern.compile("alt\\s*=\\s*&quot;(.*?)&quot;", Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE | Pattern.DOTALL);
		Pattern pTitle = Pattern.compile("title\\s*=\\s*&quot;(.*?)&quot;", Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE | Pattern.DOTALL);
		Pattern p = Pattern.compile("\\[img(.*?)\\](.*?)\\[/img\\]", Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE | Pattern.DOTALL);
		Matcher m = p.matcher(plain);
		while (m.find())
		{
			// look for attributes in the tag
			String width = null;
			String height = null;
			String alt = null;
			String title = null;
			String attributes = m.group(1);
			Matcher m2 = pWidth.matcher(attributes);
			if (m2.find())
			{
				width = StringUtil.trimToNull(m2.group(1));
			}
			m2 = pHeight.matcher(attributes);
			if (m2.find())
			{
				height = StringUtil.trimToNull(m2.group(1));
			}
			m2 = pAlt.matcher(attributes);
			if (m2.find())
			{
				alt = StringUtil.trimToNull(m2.group(1));
			}
			m2 = pTitle.matcher(attributes);
			if (m2.find())
			{
				title = StringUtil.trimToNull(m2.group(1));
			}

			StringBuffer replacement = new StringBuffer();
			replacement.append("<img src=\"" + m.group(2) + "\"");

			if (width != null)
			{
				replacement.append(" width=\"" + width + "\"");
			}

			if (height != null)
			{
				replacement.append(" height=\"" + height + "\"");
			}

			if (alt != null)
			{
				replacement.append(" alt=\"" + alt + "\"");
			}

			if (title != null)
			{
				replacement.append(" title=\"" + title + "\"");
			}

			replacement.append(" />");

			m.appendReplacement(buf, Matcher.quoteReplacement(replacement.toString()));
		}
		m.appendTail(buf);

		return buf.toString();
	}

	/**
	 * Recognize html img tags, and render them in BBcode.
	 * 
	 * @param html
	 *        The text with html tags.
	 * @return The text with the tags replaced.
	 */
	protected static String imageToPlain(String html)
	{
		StringBuffer buf = new StringBuffer();

		Pattern pWidth = Pattern.compile("width\\s*=\\s*\"(.*?)\"", Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE | Pattern.DOTALL);
		Pattern pHeight = Pattern.compile("height\\s*=\\s*\"(.*?)\"", Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE | Pattern.DOTALL);
		Pattern pAlt = Pattern.compile("alt\\s*=\\s*\"(.*?)\"", Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE | Pattern.DOTALL);
		Pattern pTitle = Pattern.compile("title\\s*=\\s*\"(.*?)\"", Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE | Pattern.DOTALL);
		Pattern pSrc = Pattern.compile("src\\s*=\\s*\"(.*?)\"", Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE | Pattern.DOTALL);
		Pattern p = Pattern.compile("<img(.*?)/>", Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE | Pattern.DOTALL);
		Matcher m = p.matcher(html);
		while (m.find())
		{
			// look for attributes
			String width = null;
			String height = null;
			String alt = null;
			String title = null;
			String src = null;
			Matcher m2 = pWidth.matcher(m.group(1));
			if (m2.find())
			{
				width = StringUtil.trimToNull(m2.group(1));
			}
			m2 = pHeight.matcher(m.group());
			if (m2.find())
			{
				height = StringUtil.trimToNull(m2.group(1));
			}
			m2 = pAlt.matcher(m.group());
			if (m2.find())
			{
				alt = StringUtil.trimToNull(m2.group(1));
			}
			m2 = pTitle.matcher(m.group());
			if (m2.find())
			{
				title = StringUtil.trimToNull(m2.group(1));
			}
			m2 = pSrc.matcher(m.group());
			if (m2.find())
			{
				src = StringUtil.trimToNull(m2.group(1));
			}

			StringBuffer replacement = new StringBuffer();
			replacement.append("[img");

			if (width != null)
			{
				replacement.append(" width=\"" + width + "\"");
			}

			if (height != null)
			{
				replacement.append(" height=\"" + height + "\"");
			}

			if (alt != null)
			{
				replacement.append(" alt=\"" + alt + "\"");
			}

			if (title != null)
			{
				replacement.append(" title=\"" + title + "\"");
			}

			replacement.append("]" + src + "[/img]");

			m.appendReplacement(buf, Matcher.quoteReplacement(replacement.toString()));
		}

		m.appendTail(buf);

		return buf.toString();
	}

	/**
	 * Recognize BBCode [b] tags and render them in html.
	 * 
	 * @param plain
	 *        The text with the BBCode tags.
	 * @return The converted text.
	 */
	protected static String italicToHtml(String plain)
	{
		Pattern p = Pattern.compile("\\[i\\](.*?)\\[/i\\]", Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE | Pattern.DOTALL);
		Matcher m = p.matcher(plain);
		plain = m.replaceAll("<em>$1</em>");

		return plain;
	}

	/**
	 * Recognize strong and b tags in html, render it into bbcode [b]
	 * 
	 * @param html
	 * @return
	 */
	protected static String italicToPlain(String html)
	{
		Pattern p = Pattern.compile("<em>(.*?)</em>", Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE | Pattern.DOTALL);
		Matcher m = p.matcher(html);
		html = m.replaceAll("[i]$1[/i]");

		p = Pattern.compile("<i>(.*?)</i>", Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE | Pattern.DOTALL);
		m = p.matcher(html);
		html = m.replaceAll("[i]$1[/i]");

		return html;
	}

	/**
	 * Recognize BBCode [url] tags and render them in html.
	 * 
	 * @param plain
	 *        The text with the BBCode tags.
	 * @return The converted text.
	 */
	protected static String linkToHtml(String plain)
	{
		StringBuffer buf = new StringBuffer();
		Pattern p = Pattern.compile("\\[url\\s*=\\s*(.*?)](.*?)\\[/url\\]", Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE | Pattern.DOTALL);
		Matcher m = p.matcher(plain);
		while (m.find())
		{
			String url = m.group(1);
			if (!(url.startsWith("/") || (url.indexOf("://") != -1))) url = "http://" + url;

			StringBuffer replacement = new StringBuffer();
			replacement.append("<a target=\"_blank\" href=\"");
			replacement.append(url);
			replacement.append("\">");
			replacement.append(m.group(2));
			replacement.append("</a>");

			m.appendReplacement(buf, Matcher.quoteReplacement(replacement.toString()));
		}

		m.appendTail(buf);
		plain = buf.toString();

		// and the [url] format
		buf = new StringBuffer();
		p = Pattern.compile("\\[url](.*?)\\[/url\\]", Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE | Pattern.DOTALL);
		m = p.matcher(plain);
		while (m.find())
		{
			String url = m.group(1);
			if (!(url.startsWith("/") || (url.indexOf("://") != -1))) url = "http://" + url;

			StringBuffer replacement = new StringBuffer();
			replacement.append("<a target=\"_blank\" href=\"");
			replacement.append(url);
			replacement.append("\">");
			replacement.append(m.group(1));
			replacement.append("</a>");

			m.appendReplacement(buf, Matcher.quoteReplacement(replacement.toString()));
		}

		m.appendTail(buf);
		plain = buf.toString();

		return plain;
	}

	/**
	 * Recognize <a> tags and render them into BBCode
	 * 
	 * @param html
	 *        The text with the tags.
	 * @return The converted text.
	 */
	protected static String linkToPlain(String html)
	{
		// match <a> tags, collect the text within the tag, add a dash, and new line before
		Pattern p = Pattern.compile("<a.*?href\\s*=\\s*\"(.*?)\".*?>(.*?)</a>", Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE | Pattern.DOTALL);
		Matcher m = p.matcher(html);
		html = m.replaceAll("[url=$1]$2[/url]");
		return html;
	}

	protected static String listToPlain(String html)
	{
		// match <ul> and <ol> and <dl> tags, collect the text within the tag, and surround with /n like a div
		Pattern p = Pattern.compile("<(ul|ol|dl).*?>(.*?)</\\1>", Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE | Pattern.DOTALL);
		Matcher m = p.matcher(html);
		html = m.replaceAll("\n$2\n");
		return html;
	}

	protected static String liToPlain(String html)
	{
		// match <li> tags, collect the text within the tag, add a dash, and new line before
		Pattern p = Pattern.compile("<li.*?>(.*?)</li>", Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE | Pattern.DOTALL);
		Matcher m = p.matcher(html);
		html = m.replaceAll("\n- $1");
		return html;
	}

	protected static String pToPlain(String html)
	{
		// match <p> and </o> tags, replace with a new line
		Pattern p = Pattern.compile("<p.*?>", Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE | Pattern.DOTALL);
		Matcher m = p.matcher(html);
		html = m.replaceAll("\n");

		p = Pattern.compile("</p>", Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE | Pattern.DOTALL);
		m = p.matcher(html);
		html = m.replaceAll("\n");

		return html;
	}

	/**
	 * Recognize BBCode [b] tags and render them in html.
	 * 
	 * @param plain
	 *        The text with the BBCode tags.
	 * @return The converted text.
	 */
	protected static String strikeToHtml(String plain)
	{
		Pattern p = Pattern.compile("\\[s\\](.*?)\\[/s\\]", Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE | Pattern.DOTALL);
		Matcher m = p.matcher(plain);
		plain = m.replaceAll("<strike>$1</strike>");

		return plain;
	}

	/**
	 * Recognize strong and b tags in html, render it into bbcode [b]
	 * 
	 * @param html
	 * @return
	 */
	protected static String strikeToPlain(String html)
	{
		Pattern p = Pattern.compile("<strike>(.*?)</strike>", Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE | Pattern.DOTALL);
		Matcher m = p.matcher(html);
		html = m.replaceAll("[s]$1[/s]");

		return html;
	}

	protected static String tagsToPlain(String html)
	{
		Pattern p = Pattern.compile("<.*?>", Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE | Pattern.DOTALL);
		Matcher m = p.matcher(html);
		html = m.replaceAll("");

		return html;
	}

	/**
	 * Recognize BBCode [b] tags and render them in html.
	 * 
	 * @param plain
	 *        The text with the BBCode tags.
	 * @return The converted text.
	 */
	protected static String underlineToHtml(String plain)
	{
		Pattern p = Pattern.compile("\\[u\\](.*?)\\[/u\\]", Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE | Pattern.DOTALL);
		Matcher m = p.matcher(plain);
		plain = m.replaceAll("<u>$1</u>");

		return plain;
	}

	/**
	 * Recognize strong and b tags in html, render it into bbcode [b]
	 * 
	 * @param html
	 * @return
	 */
	protected static String underlineToPlain(String html)
	{
		Pattern p = Pattern.compile("<u>(.*?)</u>", Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE | Pattern.DOTALL);
		Matcher m = p.matcher(html);
		html = m.replaceAll("[u]$1[/u]");

		return html;
	}

	/**
	 * Recognize html variant of an embedded YouTube video, and render them in BBcode.
	 * 
	 * @param html
	 *        The text with html tags.
	 * @return The text with the tags replaced.
	 */
	protected static String youtubeAToPlain(String html)
	{
		StringBuffer buf = new StringBuffer();

		Pattern pWidth = Pattern.compile("width\\s*=\\s*\"(.*?)\"", Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE | Pattern.DOTALL);
		Pattern pHeight = Pattern.compile("height\\s*=\\s*\"(.*?)\"", Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE | Pattern.DOTALL);
		Pattern p = Pattern.compile("<iframe(.*?www.youtube.com/embed/(.*?)[\"\\?].*?)>.*?</iframe>", Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE
				| Pattern.DOTALL);
		Matcher m = p.matcher(html);
		while (m.find())
		{
			// look for attributes
			String width = null;
			String height = null;
			Matcher m2 = pWidth.matcher(m.group(1));
			if (m2.find())
			{
				width = StringUtil.trimToNull(m2.group(1));
			}
			m2 = pHeight.matcher(m.group());
			if (m2.find())
			{
				height = StringUtil.trimToNull(m2.group(1));
			}

			StringBuffer replacement = new StringBuffer();
			replacement.append("[youtube");

			if (width != null)
			{
				replacement.append(" width=\"" + width + "\"");
			}

			if (height != null)
			{
				replacement.append(" height=\"" + height + "\"");
			}

			replacement.append("]" + m.group(2) + "[/youtube]");

			m.appendReplacement(buf, Matcher.quoteReplacement(replacement.toString()));
		}

		m.appendTail(buf);

		return buf.toString();
	}

	/**
	 * Recognize html variant of an embedded YouTube video, and render them in BBcode.
	 * 
	 * @param html
	 *        The text with html tags.
	 * @return The text with the tags replaced.
	 */
	protected static String youtubeBToPlain(String html)
	{
		StringBuffer buf = new StringBuffer();

		Pattern pWidth = Pattern.compile("width\\s*=\\s*\"(.*?)\"", Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE | Pattern.DOTALL);
		Pattern pHeight = Pattern.compile("height\\s*=\\s*\"(.*?)\"", Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE | Pattern.DOTALL);
		Pattern p = Pattern.compile("<object.*?www.youtube.com/v/.*?>.*?<embed(.*?www.youtube.com/v/(.*?)[\"\\?].*?)>.*?</object>",
				Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE | Pattern.DOTALL);
		Matcher m = p.matcher(html);
		while (m.find())
		{
			// look for attributes
			String width = null;
			String height = null;
			Matcher m2 = pWidth.matcher(m.group(1));
			if (m2.find())
			{
				width = StringUtil.trimToNull(m2.group(1));
			}
			m2 = pHeight.matcher(m.group());
			if (m2.find())
			{
				height = StringUtil.trimToNull(m2.group(1));
			}

			StringBuffer replacement = new StringBuffer();
			replacement.append("[youtube");

			if (width != null)
			{
				replacement.append(" width=\"" + width + "\"");
			}

			if (height != null)
			{
				replacement.append(" height=\"" + height + "\"");
			}

			replacement.append("]" + m.group(2) + "[/youtube]");

			m.appendReplacement(buf, Matcher.quoteReplacement(replacement.toString()));
		}

		m.appendTail(buf);

		return buf.toString();
	}

	/**
	 * Recognize html variant of an embedded YouTube video, and render them in BBcode.
	 * 
	 * @param html
	 *        The text with html tags.
	 * @return The text with the tags replaced.
	 */
	protected static String youtubeCToPlain(String html)
	{
		StringBuffer buf = new StringBuffer();

		Pattern pWidth = Pattern.compile("width\\s*=\\s*\"(.*?)\"", Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE | Pattern.DOTALL);
		Pattern pHeight = Pattern.compile("height\\s*=\\s*\"(.*?)\"", Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE | Pattern.DOTALL);
		Pattern p = Pattern.compile("<embed(.*?www.youtube.com/v/(.*?)[\"\\?].*?)>.*?</embed>", Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE
				| Pattern.DOTALL);
		Matcher m = p.matcher(html);
		while (m.find())
		{
			// look for attributes
			String width = null;
			String height = null;
			Matcher m2 = pWidth.matcher(m.group(1));
			if (m2.find())
			{
				width = StringUtil.trimToNull(m2.group(1));
			}
			m2 = pHeight.matcher(m.group());
			if (m2.find())
			{
				height = StringUtil.trimToNull(m2.group(1));
			}

			StringBuffer replacement = new StringBuffer();
			replacement.append("[youtube");

			if (width != null)
			{
				replacement.append(" width=\"" + width + "\"");
			}

			if (height != null)
			{
				replacement.append(" height=\"" + height + "\"");
			}

			replacement.append("]" + m.group(2) + "[/youtube]");

			m.appendReplacement(buf, Matcher.quoteReplacement(replacement.toString()));
		}

		m.appendTail(buf);

		return buf.toString();
	}

	/**
	 * Recognize BBCode [youtube] tags and render them in html.
	 * 
	 * @param plain
	 *        The text with the BBCode tags.
	 * @return The converted text.
	 */
	protected static String youtubeToHtml(String plain)
	{
		StringBuffer buf = new StringBuffer();

		Pattern pWidth = Pattern.compile("width\\s*=\\s*&quot;(.*?)&quot;", Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE | Pattern.DOTALL);
		Pattern pHeight = Pattern.compile("height\\s*=\\s*&quot;(.*?)&quot;", Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE | Pattern.DOTALL);
		Pattern p = Pattern.compile("\\[youtube(.*?)\\](.*?)\\[/youtube\\]", Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE | Pattern.DOTALL);
		Matcher m = p.matcher(plain);
		while (m.find())
		{
			// look for attributes in the tag
			String width = null;
			String height = null;
			String attributes = m.group(1);
			Matcher m2 = pWidth.matcher(attributes);
			if (m2.find())
			{
				width = StringUtil.trimToNull(m2.group(1));
			}
			m2 = pHeight.matcher(attributes);
			if (m2.find())
			{
				height = StringUtil.trimToNull(m2.group(1));
			}

			StringBuffer replacement = new StringBuffer();
			replacement.append("<iframe src=\"http://www.youtube.com/embed/" + m.group(2) + "\"");

			if (width != null)
			{
				replacement.append(" width=\"" + width + "\"");
			}

			if (height != null)
			{
				replacement.append(" height=\"" + height + "\"");
			}

			replacement.append(" frameborder=\"0\"></iframe>");

			m.appendReplacement(buf, Matcher.quoteReplacement(replacement.toString()));
		}
		m.appendTail(buf);

		return buf.toString();
	}

	/**
	 * Recognize html encoding of embedded youtube videos, and render them in BBcode.
	 * 
	 * @param html
	 *        The text with html tags.
	 * @return The text with the tags replaced.
	 */
	protected static String youtubeToPlain(String html)
	{
		html = youtubeAToPlain(html);
		html = youtubeBToPlain(html);
		html = youtubeCToPlain(html);

		return html;
	}
}
