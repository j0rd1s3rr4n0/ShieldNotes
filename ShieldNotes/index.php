<?php require_once('header.php'); ?>
<?PHP
/**  
 *?  /$$$$$$$  /$$$$$$$   /$$$$$$  /$$                                                                                                                              /$$$$$$$  /$$$$$$$   /$$$$$$  /$$                              /$$$$$$$  /$$$$$$$   /$$$$$$  /$$                             
 *? | $$__  $$| $$__  $$ /$$__  $$| $$                             
 *? | $$  \ $$| $$  \ $$| $$  \__/| $$  /$$$$$$   /$$$$$$$ /$$$$$$$
 *? | $$  | $$| $$$$$$$ | $$      | $$ |____  $$ /$$_____//$$_____/
 *? | $$  | $$| $$__  $$| $$      | $$  /$$$$$$$|  $$$$$$|  $$$$$$ 
 *? | $$  | $$| $$  \ $$| $$    $$| $$ /$$__  $$ \____  $$\____  $$
 *? | $$$$$$$/| $$$$$$$/|  $$$$$$/| $$|  $$$$$$$ /$$$$$$$//$$$$$$$/
 *? |_______/ |_______/  \______/ |__/ \_______/|_______/|_______/
 **/
?>
<?php
class Database
{
    private $db;
    private $db2;

    public function __construct()
    {
        //connect to the first sqlite database for notes
        $this->db = new PDO('sqlite:notes.db');
        //create the notes table if it doesn't exist
        $this->db->exec("CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY, title TEXT, content TEXT, private_key_code TEXT, fecha_fin DATETIME)");
        //connect to the second sqlite database for keys
        $this->db2 = new PDO('sqlite:keys.db');
        //create the keys table if it doesn't exist
        $this->db2->exec("CREATE TABLE IF NOT EXISTS keys (private_key_code TEXT PRIMARY KEY, private_key TEXT, public_key TEXT)");
    }

    public function addNote($title, $content)
    {
        //generate new RSA key pair
        $config = array(
            "private_key_bits" => 2048,
            "private_key_type" => OPENSSL_KEYTYPE_RSA,
        );
        $res = openssl_pkey_new($config);

        //extract the private key from the pair
        openssl_pkey_export($res, $privatekey);

        //extract the public key from the pair
        $publickey = openssl_pkey_get_details($res);
        $publickey = $publickey["key"];

        //generate a private key code
        $private_key_code = bin2hex(random_bytes(5));

        //add the public key to the keys table
        $stmt = $this->db2->prepare("INSERT INTO keys (private_key_code,private_key, public_key) VALUES (?,?,?)");
        $stmt->execute(array($private_key_code, $privatekey, $publickey));

        //encrypt the note content
        openssl_public_encrypt($content, $ciphertext, $publickey);
        $ciphertext = base64_encode($ciphertext);

        //add the note to the notes table
        $expiration_date = date('Y-m-d H:i:s', strtotime('+24 hours'));
        $stmt = $this->db->prepare("INSERT INTO notes (title, content, private_key_code, fecha_fin) VALUES (?,?,?,?)");
        $stmt->execute(array($title, $ciphertext, $private_key_code, $expiration_date));
        $note_id = $this->db->lastInsertId();
        return array('note_id' => $note_id, 'private_key_code' => $private_key_code);
    }

    public function viewNote($id, $private_key_code)
    {
        //query the notes table to get the note
        $stmt = $this->db->prepare("SELECT * FROM notes WHERE id = ?");
        $stmt->execute(array($id));
        $note = $stmt->fetch();
        echo '</br></br>';
        if ($note['fecha_fin'] < date('Y-m-d H:i:s')) {
            $this->deleteNote($_REQUEST['id']);
        }
        //query the keys table to get the private key
        $stmt = $this->db2->prepare("SELECT private_key FROM keys WHERE private_key_code = ?");
        $stmt->execute(array($private_key_code));
        $key = $stmt->fetch();

        if ($key) {
            //decrypt the note content
            $ciphertext = base64_decode($note['content']);

            //Prepara la llave privada
            $privateKey = openssl_get_privatekey($key['private_key']);
            if (!openssl_private_decrypt($ciphertext, $plaintext, $privateKey)) {
                echo openssl_error_string();
                die();
            } else {
                $this->deleteNote($note['id']);
                return array('title' => $note['title'], 'content' => $plaintext);
            }

            //return the note
            //return array('title' => $note['title'], 'content' => $plaintext);
        } else {
            print_r("ERRORR");
            echo '</br></br>';
            return false;
        }
    }
    public function deleteNote($id)
    {
        // Consultar la clave privada correspondiente en la tabla "keys" utilizando el código de clave privada.
        $stmt = $this->db->prepare("SELECT private_key_code FROM notes WHERE id = ?");
        $stmt->execute(array($id));
        $private_key_code = $stmt->fetch()['private_key_code'];

        // Eliminar la nota de la tabla "notes" utilizando su ID.
        $stmt = $this->db->prepare("DELETE FROM notes WHERE id = ?");
        $stmt->execute(array($id));

        // Eliminar la clave privada de la tabla "keys" utilizando el código de clave privada.
        $stmt = $this->db2->prepare("DELETE FROM keys WHERE private_key_code = ?");
        $stmt->execute(array($private_key_code));

        // verificar si la eliminación tuvo éxito
        if ($stmt->rowCount() > 0) {
            return true;
        } else {
            return false;
        }
    }
}


$database = new Database();

function formatKey($note_id, $private_key_code)
{
    $note_id = strval($note_id);
    if (strlen($note_id) % 2 !== 0) {
        $note_id = '0' . $note_id;
    }
    $key = $note_id . $private_key_code;
    $chunks = str_split($key, 2);
    return implode(':', $chunks);
}

function splitKey($key)
{
    $chunks = explode(':', $key);
    $note_id = "";
    $private_key_code = "";
    for ($i = 0; $i < count($chunks); $i++) {
        if ($i < count($chunks) - 5) {
            $note_id .= $chunks[$i];
        } else {
            $private_key_code .= $chunks[$i];
        }
    }
    return array('note_id' => $note_id, 'private_key_code' => $private_key_code);
}


?>


<?PHP
$currentUrl = $_SERVER['HTTP_HOST'];
/***
 *?    ██╗  ██╗████████╗███╗   ███╗██╗     
 *?    ██║  ██║╚══██╔══╝████╗ ████║██║     
 *?    ███████║   ██║   ██╔████╔██║██║     
 *?    ██╔══██║   ██║   ██║╚██╔╝██║██║     
 *?    ██║  ██║   ██║   ██║ ╚═╝ ██║███████╗
 *?    ╚═╝  ╚═╝   ╚═╝   ╚═╝     ╚═╝╚══════╝
 *?                                        
 */
?>


<?php if (isset($_REQUEST['crear'])) { ?>
    <script src="//cdn.tailwindcss.com"></script>

    <canvas class="orb-canvas"></canvas>
    <!-- Overlay -->
    <div class="overlay">
        <!-- Overlay inner wrapper -->
        <div class="overlay__inner">
            <!-- Title -->
            <h1 class="overlay__title"><span class="text-gradient">ShieldNotes</span> - Safe Sharing</h1>
            <!-- Description -->
            <p class="overlay__description"><strong>Comparte</strong> <i>textos,</i> <i>imagenes ,</i> <i>nombres de usuario</i> y <i>contraseñas de</i> <strong>forma segura!</strong></p>
            <!--  Buttons -->
            <div class="overlay__btns selector_inputs" style="width: auto;display: inline-block;float:right;margin-right: -12vw;margin-bottom: 10pt;">
                <script src="//cdnjs.cloudflare.com/ajax/libs/jquery/2.1.3/jquery.min.js"></script>

            </div>
            <link rel="stylesheet" href="//stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css">
            <script>
                function alertValue() {
                    alert("El valor seleccionado ha cambiado a: " + document.getElementById("formulario").children[0].children[0].value)
                }
                document.addEventListener("DOMContentLoaded", () => {
                    let e = document.getElementById("formulario");
                    e && e.addEventListener("change", () => {
                        alertValue()
                    })
                });
                ! function(e) {
                    e.fn.ddslick = function(d) {
                        return t[d] ? t[d].apply(this, Array.prototype.slice.call(arguments, 1)) : "object" != typeof d && d ? void e.error("Method " + d + " does not exists.") : t.init.apply(this, arguments)
                    };
                    var t = {},
                        d = {
                            data: [],
                            keepJSONItemsOnTop: !1,
                            width: 260,
                            height: null,
                            background: "#eee",
                            selectText: "",
                            defaultSelectedIndex: null,
                            truncateDescription: !0,
                            imagePosition: "left",
                            showSelectedHTML: !0,
                            clickOffToClose: !0,
                            onSelected: function() {}
                        };

                    function i(e, t) {
                        var d, i, s, n, a = e.data("ddslick"),
                            l = e.find(".dd-selected"),
                            c = l.siblings(".dd-selected-value"),
                            r = (e.find(".dd-options"), l.siblings(".dd-pointer"), e.find(".dd-option").eq(t)),
                            p = r.closest("li"),
                            u = a.settings,
                            g = a.settings.data[t];
                        e.find(".dd-option").removeClass("dd-option-selected"), r.addClass("dd-option-selected"), a.selectedIndex = t, a.selectedItem = p, a.selectedData = g, u.showSelectedHTML ? l.html((g.imageSrc ? '<img class="dd-selected-image' + ("right" == u.imagePosition ? " dd-image-right" : "") + '" src="' + g.imageSrc + '" />' : "") + (g.text ? '<label class="dd-selected-text">' + g.text + "</label>" : "") + (g.description ? '<small class="dd-selected-description dd-desc' + (u.truncateDescription ? " dd-selected-description-truncated" : "") + '" >' + g.description + "</small>" : "")) : l.html(g.text), c.val(g.value), a.original.val(g.value), e.data("ddslick", a), o(e), i = (d = e).find(".dd-select").css("height"), s = d.find(".dd-selected-description"), n = d.find(".dd-selected-image"), s.length <= 0 && n.length > 0 && d.find(".dd-selected-text").css("lineHeight", i), "function" == typeof u.onSelected && u.onSelected.call(this, a)
                    }

                    function s(t) {
                        var d = t.find(".dd-select"),
                            i = d.siblings(".dd-options"),
                            s = d.find(".dd-pointer"),
                            o = i.is(":visible");
                        e(".dd-click-off-close").not(i).slideUp(50), e(".dd-pointer").removeClass("dd-pointer-up"), o ? (i.slideUp("fast"), s.removeClass("dd-pointer-up")) : (i.slideDown("fast"), s.addClass("dd-pointer-up")),
                            function t(d) {
                                d.find(".dd-option").each(function() {
                                    var t = e(this),
                                        i = t.css("height"),
                                        s = t.find(".dd-option-description"),
                                        o = d.find(".dd-option-image");
                                    s.length <= 0 && o.length > 0 && t.find(".dd-option-text").css("lineHeight", i)
                                })
                            }(t)
                    }

                    function o(e) {
                        e.find(".dd-options").slideUp(50), e.find(".dd-pointer").removeClass("dd-pointer-up").removeClass("dd-pointer-up")
                    }
                    e("#css-ddslick").length <= 0 && e('<style id="css-ddslick" type="text/css">.dd-select{ border-radius:2px; border:solid 1px #ccc; position:relative; cursor:pointer;}.dd-desc { color:#aaa; display:block; overflow: hidden; font-weight:normal; line-height: 1.4em; }.dd-selected{ overflow:hidden; display:block; padding:10px; font-weight:bold;}.dd-pointer{ width:0; height:0; position:absolute; right:10px; top:50%; margin-top:-3px;}.dd-pointer-down{ border:solid 5px transparent; border-top:solid 5px #000; }.dd-pointer-up{border:solid 5px transparent !important; border-bottom:solid 5px #000 !important; margin-top:-8px;}.dd-options{ border:solid 1px #ccc; border-top:none; list-style:none; box-shadow:0px 1px 5px #ddd; display:none; position:absolute; z-index:2000; margin:0; padding:0;background:#fff; overflow:auto;}.dd-option{ padding:10px; display:block; border-bottom:solid 1px #ddd; overflow:hidden; text-decoration:none; color:#333; cursor:pointer;-webkit-transition: all 0.25s ease-in-out; -moz-transition: all 0.25s ease-in-out;-o-transition: all 0.25s ease-in-out;-ms-transition: all 0.25s ease-in-out; }.dd-options > li:last-child > .dd-option{ border-bottom:none;}.dd-option:hover { background: #0056b3; border: #f3f3f3; color: white !important; }.dd-selected-description-truncated { text-overflow: ellipsis; white-space:nowrap; }.dd-option-selected { background:#f6f6f6; }.dd-option-image, .dd-selected-image { vertical-align:middle; float:left; margin-right:5px; max-width:34px;}.dd-image-right { float:right; margin-right:15px; margin-left:5px;}.dd-container{ position:relative;}​ .dd-selected-text { font-weight:bold}​</style>').appendTo("head"), t.init = function(t) {
                        var t = e.extend({}, d, t);
                        return this.each(function() {
                            var d = e(this);
                            if (!d.data("ddslick")) {
                                var o = [];
                                t.data, d.find("option").each(function() {
                                    var t = e(this),
                                        d = t.data();
                                    o.push({
                                        text: e.trim(t.text()),
                                        value: t.val(),
                                        selected: t.is(":selected"),
                                        description: d.description,
                                        imageSrc: d.imagesrc
                                    })
                                }), t.keepJSONItemsOnTop ? e.merge(t.data, o) : t.data = e.merge(o, t.data);
                                var n = d,
                                    a = e('<div id="' + d.attr("id") + '"></div>');
                                d.replaceWith(a), (d = a).addClass("dd-container").append('<div class="dd-select" style="border-radius: 8pt;background: rgba(255, 255, 255, 0.375) !important;width: 260px;border: 2px solid black;"><input class="dd-selected-value" type="hidden" /><a class="dd-selected" style="background-color:transparent !important;"></a><span class="dd-pointer dd-pointer-down"></span></div>').append('<ul class="dd-options" style="width: 350px;border-radius: 8pt;display: block;margin-top:8pt;border:1px solid #000"></ul>');
                                var o = d.find(".dd-select"),
                                    l = d.find(".dd-options");
                                l.css({
                                    width: t.width
                                }), o.css({
                                    width: t.width,
                                    background: t.background
                                }), d.css({
                                    width: t.width
                                }), null != t.height && l.css({
                                    height: t.height,
                                    overflow: "auto"
                                }), e.each(t.data, function(e, d) {
                                    d.selected && (t.defaultSelectedIndex = e), l.append('<li><a class="dd-option">' + (d.value ? ' <input class="dd-option-value" type="hidden" value="' + d.value + '" />' : "") + (d.imageSrc ? ' <img class="dd-option-image' + ("right" == t.imagePosition ? " dd-image-right" : "") + '" src="' + d.imageSrc + '" />' : "") + (d.text ? ' <label class="dd-option-text">' + d.text + "</label>" : "") + (d.description ? ' <small class="dd-option-description dd-desc">' + d.description + "</small>" : "") + "</a></li>")
                                });
                                var c = {
                                    settings: t,
                                    original: n,
                                    selectedIndex: -1,
                                    selectedItem: null,
                                    selectedData: null
                                };
                                (d.data("ddslick", c), t.selectText.length > 0 && null == t.defaultSelectedIndex) ? d.find(".dd-selected").html(t.selectText): i(d, null != t.defaultSelectedIndex && t.defaultSelectedIndex >= 0 && t.defaultSelectedIndex < t.data.length ? t.defaultSelectedIndex : 0), d.find(".dd-select").on("click.ddslick", function() {
                                    s(d)
                                }), d.find(".dd-option").on("click.ddslick", function() {
                                    i(d, e(this).closest("li").index())
                                }), t.clickOffToClose && (l.addClass("dd-click-off-close"), d.on("click.ddslick", function(e) {
                                    e.stopPropagation()
                                }), e("body").on("click", function() {
                                    e(".dd-click-off-close").slideUp(50).siblings(".dd-select").find(".dd-pointer").removeClass("dd-pointer-up")
                                }))
                            }
                        })
                    }, t.select = function(t) {
                        return this.each(function() {
                            t.index && i(e(this), t.index)
                        })
                    }, t.open = function() {
                        return this.each(function() {
                            var t = e(this);
                            t.data("ddslick") && s(t)
                        })
                    }, t.close = function() {
                        return this.each(function() {
                            var t = e(this);
                            t.data("ddslick") && o(t)
                        })
                    }, t.destroy = function() {
                        return this.each(function() {
                            var t = e(this),
                                d = t.data("ddslick");
                            if (d) {
                                var i = d.original;
                                t.removeData("ddslick").unbind(".ddslick").replaceWith(i)
                            }
                        })
                    }
                }(jQuery), jQuery('option[value="user"]').attr("data-imagesrc", "images/icons/user.png"), jQuery('option[value="pass"]').attr("data-imagesrc", "images/icons/password.png"), jQuery('option[value="text"]').attr("data-imagesrc", "images/icons/text.png"), jQuery('option[value="file"]').attr("data-imagesrc", "images/icons/file.png"), jQuery('option[value="user_n_pass"]').attr("data-imagesrc", "images/icons/login.png"), jQuery('option[value="user_pass_text"]').attr("data-imagesrc", "images/icons/user_pass_text.png"), jQuery('option[value="user_pass_file"]').attr("data-imagesrc", "images/icons/user_pass_file.png"), jQuery('option[value="file_pass"]').attr("data-imagesrc", "images/icons/file_pass.png"), jQuery(function() {
                    jQuery("#formulario").ddslick()
                });
                var s = "";

                function func() {
                    if (valorinput = document.querySelector("#formulario > div > input"), formgen = document.getElementById("formgen"), "" != valorinput.value) {
                        switch (valor = "", valorinput.value) {
                            case "user":
                                valor = '<input type="text" maxlenght="245" placeholder="UserName" id="username" class="overlay__btn overlay__btn--transparent tal">';
                                break;
                            case "pass":
                                valor = '<input type="text" maxlenght="245" placeholder="P@sSW0rD!1" id="password" class="overlay__btn overlay__btn--transparent tal">';
                                break;
                            case "text":
                                valor = '<textarea id="sectext" maxlenght="245" placeholder="Escriba aqu\xed..." class="overlay__btn overlay__btn--transparent talon" rows=9></textarea>';
                                break;
                            case "file":
                                valor = '<label class="block"><span class="sr-only">Choose profile photo</span><input type="file" class="block w-full text-sm text-gray-500file:mr-4 file:py-2 file:px-4file:rounded-md file:border-0file:text-sm file:font-semiboldfile:bg-blue-500 file:text-whitehover:file:bg-blue-600"/></label>';
                                break;
                            default:
                                valor = "default"
                        }
                        let e = 0;
                        for (; formgen.firstChild;) formgen.removeChild(formgen.lastChild), e++;
                        let l = document.createElement("div");
                        l.className = "overlay__btns", l.innerHTML = valor, formgen.appendChild(l), s = valorinput.value
                    }
                }
            </script>

            <hr style="margin:15pt;background-color:transparent;border:0px solid; transparent;">

            <div class="overlay__btns" style="margin:7pt;" id="formgen">
                <div style="width: 100%;max-width: 100%;">
                    <textarea id="sectext" maxlength="245" placeholder="Escriba aquí..."
                        class="overlay__btn overlay__btn--transparent talo" style="width:100% !important;text-align:jutify;"
                        rows=9 oninput="checkLength()"></textarea>
                    <p id="contador" style="text-align:right;">0/245</p>
                </div>
            </div>

            <div class="overlay__btns" style="margin-top:20pt;">
                <button onclick="generateSubmit()" class="overlay__btn overlay__btn--colors talo">
                    <span class="overlay__btn-emoji">⚙️</span>
                    Generar Enlace
                </button>
            </div>
        </div>
    </div>
    <script>
        function checkLength() {
            var e = document.getElementById("sectext").value.length;
            document.getElementById("contador").innerHTML = e + "/245"
        }

        function generateSubmit() {
            var e = "Undefined",
                t = "Username";
            if (document.querySelector("#username")) e = document.querySelector("#username").value, t = "Username";
            else if (document.querySelector("#password")) e = document.querySelector("#password").value, t = "Contrase\xf1a";
            else if (document.querySelector("#sectext")) {
                if (e = document.querySelector("#sectext").value, t = "Text", e.length > 245) {
                    alert("El campo de texto no puede tener m\xe1s de 245 caracteres");
                    return
                }
            } else document.querySelector("#formgen > div > label > input") ? (e = document.querySelector("#formgen > div > label > input").value, t = "Archivo") : (alert("You can't do it!"), e = void 0);
            if ("string" == typeof e && e.trim().length > 0) {
                let r = document.createElement("form");
                <?php $_SERVER['HTTP_HOST'] . "AAAA"; ?>
                r.action = "http://<?php echo $_SERVER['HTTP_HOST']; ?>", r.method = "POST";
                var n = document.createElement("input");
                n.setAttribute("name", "title"), n.setAttribute("value", t);
                var a = document.createElement("input");
                a.setAttribute("name", "content"), a.setAttribute("value", e);
                var u = document.createElement("input");
                u.setAttribute("type", "submit"), u.setAttribute("name", "submit"), u.setAttribute("value", "Submit"), r.appendChild(u), r.appendChild(n), r.appendChild(a), r.setAttribute("enctype", "multipart/form-data"), document.body.appendChild(r), r ? console.log(r.submit.click()) : setTimeout(function() {
                    alert("error")
                }, 500)
            } else alert("No se puede Enviar Una Cadena Vac\xeda")
        }
    </script>
<?php } else if (isset($_REQUEST['id']) && isset($_REQUEST['private_key_code'])) {
    $note = $database->viewNote($_REQUEST['id'], $_REQUEST['private_key_code']); 
?>
    <canvas class="orb-canvas"></canvas>
    <!-- Overlay -->
    <div class="overlay">
        <!-- Overlay inner wrapper -->
        <div class="overlay__inner">
            <!-- Title -->
            <h1 class="overlay__title"><span class="text-gradient">ShieldNotes</span> - Safe Sharing</h1>
            <!-- Description -->
            <p class="overlay__description"><strong>Comparte</strong> <i>textos,</i> <i>imagenes ,</i> <i>nombres de
                    usuario</i> y <i>contraseñas de</i> <strong>forma segura!</strong></p>
            <!--  Buttons -->
            <hr style="margin:10pt;background-color:transparent;border:0px solid; transparent;">
            <!--div class="overlay__btns">
                <input type="text" value="P@sSW0rD!1" id="password" class="overlay__btn overlay__btn--transparent tal"
                    readonly>
                <button onclick="copyPassword()" class="overlay__btn overlay__btn--colors talo">
                    Copy Password
                    <span class="overlay__btn-emoji">📎</span>
                </button>
            </div-->

            <hr style="margin:10pt;background-color:transparent;border:0px solid; transparent;">
    <?php if (isset($note) && $note != false) {
        $user_pass_lst = ['Username', 'Contraseña', 'File', 'Password'];
        $txts = ['Nombre de Usuario', 'Contraseña', 'Archivo', 'P@ssw0rd!'];

        if (in_array($note['title'], $user_pass_lst)) {
            $index = array_search($note['title'], $user_pass_lst);
    ?>
            <div class="overlay__btns" style="margin-top:15pt !Important;">
                <h4><?php echo $txts[$index]?></h4>
            </div>

            <div class="overlay__btns" style="margin-top:15pt !Important;">
                <input type="text" value="<?php echo $note['content']?>" id="username" class="overlay__btn overlay__btn--transparent tal"
                    readonly>
                <button onclick="copyUsername()" class="overlay__btn overlay__btn--colors talo">
                    Copy <?php echo $txts[$index]?>
                    <span class="overlay__btn-emoji">📎</span>
                </button>
            </div>
    <?php
    } else {
    ?>
                    <div class="overlay__btns">
                        <h4><?php echo $note['title'] ?></h4>
                    </div>
                    <div class="overlay__btns">
                        <textarea id="sectext" class="overlay__btn overlay__btn--transparent talon" rows=9 readonly><?php echo $note['content'] ?></textarea>
                    </div>
                    <div class="overlay__btns" style="margin-top:15pt !Important;">
                        <button onclick="copyText()" class="overlay__btn overlay__btn--colors talo">
                            Copy <?php echo $note['title']; ?>
                            <span class="overlay__btn-emoji">📎</span>
                        </button>
                    </div>
    <?php
        }
    } else {
        ?><p style="color:red;">Error: Código de clave privada no válido o nota no encontrada</p><?php 
    }
    ?>
            <!--
            <div class="overlay__btns">
                <input type="text" value="UserName" id="username" class="overlay__btn overlay__btn--transparent tal"
                    readonly>
                <button onclick="copyUsername()" class="overlay__btn overlay__btn--colors talo">
                    Copy Username
                    <span class="overlay__btn-emoji">📎</span>
                </button>
            </div>-
            ->

            <hr style="margin:10pt;background-color:transparent;border:0px solid; transparent;">
            <!--<div class="overlay__btns">
            <textarea value="P@sSW0rD!1" id="sectext" class="overlay__btn overlay__btn--transparent talon" readonly rows=9>Actualmente ya no es sorprendente decir que vivimos rodeados de información o que es uno de los activos más importantes en el panorama empresarial. Ese volumen de datos se traduce en valor económico para las empresas, y por tanto, en el camino que marca su éxito o su fracaso en el futuro.
                En un mundo sumido en una transición hacia lo completamente digital, necesitamos implementar los mecanismos necesarios para proteger y gestionar la información, no solo desde el punto de vista tecnológico sino también legal.

                “No decir más de lo que haga falta, a quien haga falta y cuando haga falta” (A. Maurois), una afirmación tan sencilla como fundamental, y es que en eso se basa el mecanismo principal de protección de la información contra la revelación de secretos: los acuerdos de confidencialidad.
                </textarea>
            </div>
            <style>
            #btncpytxt{
                margin-top:30pt !important;
            }
            </style>
            <div class="overlay__btns">
                <button onclick="copyText()" id="btncpytxt" class="overlay__btn overlay__btn--colors talo">Copy Text <span
                        class="overlay__btn-emoji">📎</span></button>
            </div>-->
            <!--<button class="overlay__btn overlay__btn--transparent">
            <a href="//georgefrancis.dev/writing/create-a-generative-landing-page-and-webgl-powered-background/" target="_blank">

              View Tutorial
            </a>
          </button>


          <button class="overlay__btn overlay__btn--colors">
            <span>Randomise Colors</span>
            <span class="overlay__btn-emoji">🎨</span>
          </button>-->
        </div>
    </div>
    <?php } else if (isset($_REQUEST['submit'])) {
            //TODO ENLACE
            ?>
    <hr><br>
    <canvas class="orb-canvas"></canvas><!-- Overlay -->
    <div class="overlay">
        <!-- Overlay inner wrapper -->
        <div class="overlay__inner">
            <!-- Title -->
            <h1 class="overlay__title"><span class="text-gradient">ShieldNotes</span> - Enlace Generado</h1><!-- Description -->
            <p class="overlay__description">Se ha generado una ruta de acceso al conetnido. <i>Se le invita a compartir el siguiente <b>enlace</b></i> de <b>unica visualización</b>, <i>si el mensaje no ha sido visualizado pasadas 24h de su visualización se eliminara el contenido.</i></p>
            <!--  Buttons -->
            <hr style="margin:10pt;background-color:transparent;border:0px solid; transparent;">
            <?php
            if (isset($_REQUEST['title']) && isset($_REQUEST['content'])) {
                $result = $database->addNote($_REQUEST['title'], $_REQUEST['content']);
                $key = formatKey($result['note_id'], $result['private_key_code']);
                echo "Su código es " . formatKey($result['note_id'], $result['private_key_code']) . "" .
                    //"Su código de clave privada es: " . $result['private_key_code'] . "\n<br>Su id es: " . $result['note_id'] . 
                    "\n<br><a href=\"?tk=" . formatKey($result['note_id'], $result['private_key_code']) . '">//' . $_SERVER['HTTP_HOST'] . '/?tk=' . formatKey($result['note_id'], $result['private_key_code']) . '</a><br>';
                // echo "Nota agregada exitosamente.\n<br>Su código de clave privada es: " . $result['private_key_code'] . "\n<br> y su id es: " . $result['note_id'] . '<br> <a href="?id=' . $result['note_id'] . '&private_key_code=' . $result['private_key_code'] . '">//'.$_SERVER['HTTP_HOST'].'/?id=' . $result['note_id'] . '&private_key_code=' . $result['private_key_code'] . '</a>\n';

                //echo '<button class="overlay__btn overlay__btn--colors talo" onclick="copyUrl" value="//' . $_SERVER['HTTP_HOST'] . '/?tk=' . formatKey($result['note_id'], $result['private_key_code']) . '">Copiar Enlace</button>';



                $subject_mail = 'Te Adjunto Un Mensaje Seguro';
                $bodyMail = 'ShieldNotes - Enlace Generado%0ASe ha generado una ruta de acceso al contenido. Se le invita a compartir el siguiente enlace de única visualización, si el mensaje no ha sido visualizado pasadas 72h de su visualización se eliminara el contenido.%0A%0ASu código es ' . formatKey($result['note_id'], $result['private_key_code']) .
                    '%0A//'.$_SERVER["HTTP_HOST"].'/?tk=' . formatKey($result['note_id'], $result['private_key_code']) .
                    '%0A - Generador por ShieldNotes\n';
                $bodyMail = str_replace(array('\r\n', '\n'), '%0A', $bodyMail);
            ?>

        <script>
            function myFunctionCopy(This, element) {
                var copyText = document.getElementById(element);
                copyText.select();
                copyText.setSelectionRange(0, 99999); // For mobile devices
                navigator.clipboard.writeText(copyText.value.replace(/\\n/g, '\n'));
                //alert("Copied the text: " + copyText.value.replace(/\\n/g, '\n'));
                This.innerText = 'Enlace copiado!';
            }
        </script>
        <div class="flex justify-between items-center" style="padding: 10pt;width: 100%;text-align: center;">
            <!-- DISPLAYS NONE -->
            <input type="text" id="myInputCopy" value="https://<?php echo $_SERVER['HTTP_HOST'] . '/?tk=' . formatKey($result['note_id'], $result['private_key_code']) ?>" style="display:none;">
            <input type="text" id="a" value="https://<?php echo $_SERVER['HTTP_HOST'] . '/?tk=' . formatKey($result['note_id'], $result['private_key_code']) ?>" style="display:none;">

            <!-- DISPLAY NORMAL -->

            <button id="btn-copy-link" onclick="myFunctionCopy(this,'myInputCopy')" class="bg-gray-300 hover:bg-gray-400 py-2 px-4 rounded-md" style="margin: 2pt !important;background: linear-gradient(45deg,var(--base) 25%,var(--complimentary2));color: white;border-radius: 7pt;">
                <i class="far fa-copy"></i> Copiar enlace
            </button>
            <button onclick="javascript:window.location=\'mailto:?subject=<?php echo $subject_mail?>&body=<?php echo $bodyMail?>" id="btn-email" class="bg-gray-300 hover:bg-gray-400 py-2 px-4 rounded-md" style="margin: 2pt !important;background: var(--dark-color);border-radius: 7pt;color: white;">
                <i class="far fa-envelope"></i> Correo electrónico
            </button>

            <button id="btn-whatsapp" class="bg-green-500 hover:bg-green-600 text-white py-2 px-4 rounded-md" style="margin: 2pt !important;background: #075e54;border-radius: 7pt;">
                <i class="fab fa-whatsapp"></i> WhatsApp
            </button>

            <button id="btn-instagram" class="bg-pink-500 hover:bg-pink-600 text-white py-2 px-4 rounded-md" style="margin: 2pt !important;background: radial-gradient(circle at 33% 100%, #fed373 4%, #f15245 30%, #d92e7f 62%, #9b36b7 85%, #515ecf);border-radius: 7pt;">
                <i class="fab fa-instagram"></i> Instagram
            </button>
            <button id="btn-facebook" class="bg-blue-700 hover:bg-blue-800 text-white py-2 px-4 rounded-md" style="margin: 2pt !important;background: #4267B2;border-radius: 7pt;">
                <i class="fab fa-facebook"></i> Facebook
            </button>

            <button id="btn-twitter" class="bg-blue-500 hover:bg-blue-600 text-white py-2 px-4 rounded-md" style="margin: 2pt !important;background: #00acee;border-radius: 7pt;">
                <i class="fab fa-twitter"></i> Twitter
            </button>
            <!--
                                <button id="btn-linkedin" class="bg-indigo-500 hover:bg-indigo-600 text-white py-2 px-4 rounded-md" style="margin: 2pt !important;background: #0C63BC;border-radius: 7pt;">
                                    <i class="fab fa-linkedin"></i> LinkedIn
                                </button>

                                <button id="btn-tiktok" class="bg-black text-white hover:bg-gray-800 py-2 px-4 rounded-md" style="margin: 2pt !important;background-image: linear-gradient(45deg, #222, #444);border-radius: 7pt;">
                                    <i class="fab fa-tiktok"></i> TikTok
                                </button>
                -->
        </div>
    <?php
            }
    ?>

    </div>
    </div>


<?php
        } else if (isset($_REQUEST['show'])) {
?><canvas class="orb-canvas"></canvas><!-- Overlay -->
    <div class="overlay">
        <!-- Overlay inner wrapper -->
        <div class="overlay__inner">
            <!-- Title -->
            <h1 class="overlay__title"><span class="text-gradient">ShieldNotes</span> - Safe Sharing</h1>
            <!-- Description -->
            <p class="overlay__description"><strong>Comparte</strong> <i>textos,</i> <i>imagenes ,</i> <i>nombres de usuario</i> y <i>contraseñas de</i> <strong>forma segura!</strong></p>
            <!--  Buttons -->
            <hr style="margin:10pt;background-color:transparent;border:0px solid; transparent;">
            <!--
                <div class="overlay__btns">
                    <input type="number" placeholder="HERE ID" id="id" pattern="[0-9]" class="overlay__btn overlay__btn--transparent tal">
                </div>
                <div class="overlay__btns">
                    <input type="text" placeholder="HERE CODEHEX" id="private_key_code" pattern="/[0-9a-fA-F]+/" class="overlay__btn overlay__btn--transparent tal">
                </div>
            -->
            <form>
                <div class="overlay__btns">
                    <input type="text" placeholder="HERE CODEHEX" id="tk" name="tk" pattern="[a-fA-F0-9]{2}(:[a-fA-F0-9]{2})+" class="overlay__btn overlay__btn--transparent tal">

                </div>
                <div class="overlay__btns">
                    <button type="submit" class="overlay__btn overlay__btn--colors talo">
                        Ver Nota
                        <span class="overlay__btn-emoji">📋</span>
                    </button>
            </form>
        </div>
    </div>
    </div>
    <?php
        } else if (isset($_REQUEST['tk'])) {
            $tk = $_REQUEST['tk'];
    ?>
    //TODO PRE-SHOW
    <canvas class="orb-canvas"></canvas><!-- Overlay -->
    <div class="overlay">
        <!-- Overlay inner wrapper -->
        <div class="overlay__inner">
            <!-- Title -->
            <h1 class="overlay__title"><span class="text-gradient">ShieldNotes</span> - VISUALIZAR</h1>
            <!-- Description -->
            <p class="overlay__description" style="text-align:justify;">
                Si deseas visualizar una única nota, se te invita a hacer clic en el botón correspondiente. Al
                hacerlo, se te mostrará la nota en su totalidad para que la leas con detenimiento. Esto te permitirá
                aprovechar al máximo toda la información que contiene. Al mismo tiempo, como <b>se trata de una sola
                    visualización</b>, podrás estar seguro de que no te perderás ninguno de los detalles y que la
                información se mantendrá actualizada. Esperamos que disfrutes tu experiencia con el botón de una
                sola visualización.


            </p>
            <?php
            $key = $_REQUEST['tk'];
            $d = splitKey($key);
            $id = $d['note_id'];
            $private_key_code = $d['private_key_code'];
            //echo $id . '<br>' . $private_key_code;
            ?>
            <form method="post" enctype="multipart/form-data">
                <div class="overlay__btns">
                    <?php
                    // TODO AQUI PONER SOLO UN INPUT HIDDEN QUE SE SEPARE ASI: id:private_key_code
                    // TODO PERO QUE private_key_code se separe cada 2 caracteres por : por lo tanto
                    // TODO QUEDARIA ASI: <id>:<private_key_code> --> 01:03:a9:r3:12:op:17:99
                    ?>
                    <input type="hidden" value="<?= $id; ?>" id="id" name="id"
                        class="overlay__btn overlay__btn--transparent tal" readonly>
                    <input type="hidden" value="<?= $private_key_code; ?>" name="private_key_code"
                        id="private_key_code" class="overlay__btn overlay__btn--transparent tal" readonly>
                    <button type="submit" class="overlay__btn overlay__btn--colors talo">
                        Visualizar Nota
                        <span class="overlay__btn-emoji">🗒️👁️</span>
                    </button>
                </div>
            </form>
        </div>
    </div>

<?php
        } else {
            //TODO HOME
?>
    <canvas class="orb-canvas"></canvas><!-- Overlay -->
    <div class="overlay">
        <!-- Overlay inner wrapper -->
        <div class="overlay__inner">
            <!-- Title -->
            <h1 class="overlay__title"><span class="text-gradient">ShieldNotes</span> - Safe Sharing</h1><!-- Description -->
            <p class="overlay__description"><strong>Comparte</strong> <i>textos,</i> <i>imagenes ,</i> <i>nombres de
                    usuario</i> y <i>contraseñas de</i> <strong>forma segura!</strong></p>
            <!--  Buttons -->
            <hr style="margin:10pt;background-color:transparent;border:0px solid; transparent;">
            <div class="overlay__btns">
                <button onclick="window.location='?show'" class="overlay__btn overlay__btn--transparent">
                    Mostrar Nota
                    <span class="overlay__btn-emoji">🔍</span>
                </button>
                <button onclick="window.location='?crear'" class="overlay__btn overlay__btn--colors talo">
                    Generar Nota
                    <span class="overlay__btn-emoji">⚙️</span>
                </button>

            </div>

            <!--<button class="overlay__btn overlay__btn--transparent">
            <a href="//georgefrancis.dev/writing/create-a-generative-landing-page-and-webgl-powered-background/" target="_blank">

              View Tutorial
            </a>
          </button>


          <button class="overlay__btn overlay__btn--colors">
            <span>Randomise Colors</span>
            <span class="overlay__btn-emoji">🎨</span>
          </button>-->
        </div>
    </div><?php } ?>

<div class=""
    style="margin-top: 50pt;width: 92vw;text-align: justify;background-color:rgba(255, 255, 255, 0.375);padding:50pt;border-radius:2vw;border:1px solid rgba(255, 255, 255, 0.125);display: inherit;">
    <h1>Política de privacidad</h1>
    <p>En ShieldNotes, la privacidad se toma muy en serio, ya que el objetivo principal del sitio es preservarla.
        Esta
        política describe las medidas tomadas por ShieldNotespara proteger la privacidad de sus usuarios.</p>
    <h4>1). Descripción del servicio</h4>
    <p>ShieldNoteses un servicio gratuito basado en la web que permite a los usuarios crear notas cifradas que
        pueden
        compartir a través de Internet como URL  únicas de un solo uso (en lo sucesivo denominadas enlaces)
        que
        caducará de forma predeterminada después de su primer acceso a través de cualquier navegador web.</p>
    <p>Como ShieldNotesno proporciona ningún medio para transmitir el enlace, el acto de enviar el enlace es
        responsabilidad total de los usuarios de ShieldNotes.</p>
    <p>Dependiendo del canal de comunicación de su elección (por ejemplo, correo electrónico, fax, SMS,
        teléfono,
        mensajería instantánea, redes sociales), puede existir un cierto riesgo de que terceros intercepten su
        comunicación, conozca el enlace comunicado y, por lo tanto, puede leer su nota.</p>
    <h4>2). Cómo se procesan las notas y sus contenidos</h4>
    <p>El enlace se genera en el navegador del usuario y en ningún momento se envía como tal a ShieldNotes. Por lo
        tanto,
        el enlace está en las manos del remitente (y luego posiblemente en las manos del receptor) solamente.
        Por lo
        tanto, no hay forma de recuperar una nota si un usuario de ShieldNotespierde el enlace.</p>
    <p>Dado que solo el enlace vincula la clave de descifrado al contenido de la nota y que ShieldNotesno tiene el
        enlace,
        en ningún momento se mantiene ninguna nota en ningún estado de formato legible en ShieldNotes. Esto asegura
        que
        nadie (incluidos los administradores de ShieldNotes) pueda leer una nota.</p>
    <p>Cuando se usa la funcionalidad predeterminada de ShieldNotes, cuando se recupera una nota, sus datos se
        eliminan por
        completo de ShieldNotes; no hay absolutamente ninguna forma de recuperarlo nuevamente.</p>
    <p>Cuando se selecciona "Mostrar opciones" y el usuario opta por un intervalo de tiempo para la eliminación
        de la
        nota, independientemente de cuántas veces se recupere la nota, la nota se eliminará solo después de
        completar el
        tiempo especificado.</p>
    <p>Después de eliminar una nota de ShieldNotes, no hay absolutamente ninguna forma de recuperarla nuevamente.
    </p>
    <p>Cuando no se recupera una nota después de 30 días, ShieldNotesla elimina permanentemente, como si se
        leyera. El
        equipo de sysadmin de ShieldNoteshará todo lo posible para proteger el sitio contra el acceso no
        autorizado, la
        modificación o la destrucción de los datos. Pero, incluso si alguien o algo pudiera obtener acceso a la
        base de
        datos, no podrían leer las notas ya que sus contenidos están encriptados y no se pueden descifrar sin
        los
        enlaces que ShieldNotesnunca tiene.</p>
    <h4>3). Procesamiento de direcciones IP</h4>
    <p>ShieldNotesno está registrando las direcciones IP; se procesan para permitir la comunicación con los
        servidores de
        ShieldNotes, pero no forman parte de los archivos de registro. Las direcciones IP se eliminan tan pronto
        como ya no
        son necesarias para fines de comunicación.</p>
    <h4>4). Datos seudónimos</h4>
    <p>El creador de la nota puede introducir datos personales en la nota. Aunque estos datos están encriptados,
        los
        datos pueden descifrarse nh4evamente y, por lo tanto, constituyen datos seudónimos (personales). En
        cualquier
        caso, no se puede deducir el creador de la nota de la base de datos de ShieldNotes, ya que ShieldNotesno
        almacena
        direcciones IP.</p>
    <p>El descifrado de los datos de la nota está en manos de los usuarios (rh4mitente y destinatario). ShieldNotes
        no
        puede descifrar la nota y acceder a los datos (personales o de otro modo) introducidos por el creador ya
        que
        ShieldNotesnunca posee la clave de descifrado que está contenida solo en el enlace.</p>
    <h4>5). Descargo de responsabilidad</h4>
    <p>Cuando una persona hace clic en el enlace de ShieldNotes, ShieldNotesdeclina cualquier responsabilidad
        relacionada con
        el contenido de la nota.</p>
    <h4>6). Divulgación de datos a terceros</h4>
    <p>ShieldNotesno comparte ni vende ninguna información a otros, ni la usa de ninguna manera que no se mencione
        en esta
        Política de privacidad.</p>
    <h4>7). Uso de cookies</h4>
    <p>ShieldNotesutiliza cookies (pequeños archivos de texto que su navegador almacena en su computadora cuando
        visita un
        sitio web) para nuestro propio interés en mejorar el uso de nuestro sitio y servicio. En algunos casos,
        también
        se utilizarán con fines promocionales. El tipo de cookies que utiliza ShieldNotesse enumeran a
        continuación:</p>
    <p style="font-style: italic;"></p>
    <p>Cookies funcionales</p>
    <p>ShieldNotesutiliza cookies persistentes para mantener una sesión en el idioma preferido del usuario y para
        registrar su notificación de que ShieldNotesutiliza cookies como se explica en esta sección. Además,
        algunas
        cookies se utilizan como parte del mecanismo de ocultación de enlaces al leer una nota, Estas cookies en
        particular deben estar habilitadas para que ShieldNotesfuncione y se eliminan inmediatamente después de
        recuperar
        la nota.</p>
    <p style="font-style: italic;"></p>
    <p>Cookies no funcionales</p>
    <p>Utilizado con fines comerciales y promocionales. Las cookies no funcionales son colocadas por terceros.
        En el
        caso de los ciudadanos europeos, estas cookies no almacenan datos personales (anuncios no
        personalizados).</p>
    <p>Si desea eliminar ciertas cookies o impedir que se almacenen en su navegador, es posible a través de la
        configuración de su navegador para las cookies. Sin embargo, si hace esto, el sitio podría no funcionar
        como se
        esperaba.</p>
    <h4>8). Niños</h4>
    <p>ShieldNotesno tiene como objetivo y no está destinado a atraer a niños menores de 16 años. Los menores
        deben
        obtener el consentimiento expreso de sus padres o tutores legales antes de acceder o usar ShieldNotes.</p>
    <h4>9). Validez de esta Política de privacidad</h4>
    <p>Tenga en cuenta que esta Política de privacidad puede cambiar de vez en cuando. Esperamos que la mayoría
        de los
        cambios sean menores. De todos modos, publicaremos cualquier cambio de Política en esta página, y si los
        cambios
        son significativos, proporcionaremos un aviso más destacado, como un mensaje en la página de inicio.
        Cada
        versión de esta Política se identificará en la parte superior de la página en su fecha de vigencia.</p>
    <h4>10). Información de contacto</h4>
    <p>Si tiene alguna pregunta sobre esta Política de privacidad u otras inquietudes relacionadas con problemas
        de
        privacidad, envíenos un correo electrónico a <?php echo $_SERVER['HTTP_HOST'];?> y le responderemos en menos de 5 días
        hábiles. Si
        no está satisfecho con el resultado de nuestra comunicación, puede remitir su queja a una autoridad
        supervisora
        local.

        <font style="vertical-align: inherit;">
            <font style="vertical-align: inherit;">ShieldNoteses un servicio proporcionado por SSSS. Los detalles
                corporativos son los siguientes:</font>
        </font>
        <br><br>
        <font style="vertical-align: inherit;"><a href="mailito:<?php echo $_SERVER['HTTP_HOST'];?>"><?php echo $_SERVER['HTTP_HOST'];?></a>
        </font>
    </p>
</div>
<script>
    if (document.querySelector("#private_key_code")) {
        input = document.querySelector("#private_key_code");
        const hexvals = 'ABCDEFabcdef0123456789';
        input.addEventListener('keyup', (e) => {

            var txt = "";
            var arr = input.value.split('');
            arr.forEach((item, index) => {
                if (hexvals.includes(item)) {
                    txt += (item);
                    return;
                }
            })
            document.querySelector("#private_key_code").value = txt;
        });
    }
    // Función para copiar la contraseña al portapapeles
    function copyPassword() {
        const passwordInput = document.getElementById('password');
        passwordInput.select();
        //document.querySelector('#password').select();
        document.execCommand('copy');
        alert('Contraseña copiada al portapapeles');
    }
    // Función para copiar el username al portapapeles
    function copyUsername() {
        const usernameInput = document.getElementById('username');
        usernameInput.select();
        //document.querySelector('#username').select();
        document.execCommand('copy');
        alert('Nombre de usuario copiado al portapapeles');
    }
    // Función para copiar el sectext al portapapeles
    function copyText() {
        const sectextInput = document.getElementById('sectext');
        sectextInput.select();
        //document.querySelector('#sectext').select();
        document.execCommand('copy');
        alert('Texto copiado al portapapeles');
    }
</script>

<script>
    // Función para copiar la contraseña al portapapeles
    function copyPassword() {
        const passwordInput = document.getElementById('password');
        passwordInput.select();
        //document.querySelector('#password').select();
        document.execCommand('copy');
        alert('Contraseña copiada al portapapeles');
    }
    // Función para copiar el username al portapapeles
    function copyUsername() {
        const usernameInput = document.getElementById('username');
        usernameInput.select();
        //document.querySelector('#username').select();
        document.execCommand('copy');
        alert('Nombre de usuario copiado al portapapeles');
    }
    // Función para copiar el sectext al portapapeles
    function copyText() {
        const sectextInput = document.getElementById('sectext');
        sectextInput.select();
        //document.querySelector('#sectext').select();
        document.execCommand('copy');
        alert('Texto copiado al portapapeles');
    }
</script>


<script id="rendered-js" type="module">
    import * as PIXI from "https://cdn.skypack.dev/pixi.js@5.x";
    import {
        KawaseBlurFilter
    } from "https://cdn.skypack.dev/@pixi/filter-kawase-blur@3.2.0";
    import SimplexNoise from "https://cdn.skypack.dev/simplex-noise@3.0.0";
    import hsl from "https://cdn.skypack.dev/hsl-to-hex";
    import debounce from "https://cdn.skypack.dev/pin/debounce@v2.2.0-nsljQIXDuyHmm6xBMrgd/mode=imports,min/optimized/debounce.js";

    // return a random number within a range
    function random(min, max) {
        return Math.random() * (max - min) + min;
    }

    // map a number from 1 range to another
    function map(n, start1, end1, start2, end2) {
        return ((n - start1) / (end1 - start1)) * (end2 - start2) + start2;
    }

    // Create a new simplex noise instance
    const simplex = new SimplexNoise();

    // ColorPalette class
    class ColorPalette {
        constructor() {
            this.setColors();
            this.setCustomProperties();
        }

        setColors() {
            // pick a random hue somewhere between 220 and 360
            this.hue = ~~random(220, 360);
            this.complimentaryHue1 = this.hue + 30;
            this.complimentaryHue2 = this.hue + 60;
            // define a fixed saturation and lightness
            this.saturation = 95;
            this.lightness = 50;

            // define a base color
            this.baseColor = hsl(this.hue, this.saturation, this.lightness);
            // define a complimentary color, 30 degress away from the base
            this.complimentaryColor1 = hsl(
                this.complimentaryHue1,
                this.saturation,
                this.lightness
            );
            // define a second complimentary color, 60 degrees away from the base
            this.complimentaryColor2 = hsl(
                this.complimentaryHue2,
                this.saturation,
                this.lightness
            );

            // store the color choices in an array so that a random one can be picked later
            this.colorChoices = [
                this.baseColor,
                this.complimentaryColor1,
                this.complimentaryColor2
            ];
        }

        randomColor() {
            // pick a random color
            return this.colorChoices[~~random(0, this.colorChoices.length)].replace(
                "#",
                "0x"
            );
        }

        setCustomProperties() {
            // set CSS custom properties so that the colors defined here can be used throughout the UI
            document.documentElement.style.setProperty("--hue", this.hue);
            document.documentElement.style.setProperty(
                "--hue-complimentary1",
                this.complimentaryHue1
            );
            document.documentElement.style.setProperty(
                "--hue-complimentary2",
                this.complimentaryHue2
            );
        }
    }

    // Orb class
    class Orb {
        // Pixi takes hex colors as hexidecimal literals (0x rather than a string with '#')
        constructor(fill = 0x000000) {
            // bounds = the area an orb is "allowed" to move within
            this.bounds = this.setBounds();
            // initialise the orb's { x, y } values to a random point within it's bounds
            this.x = random(this.bounds["x"].min, this.bounds["x"].max);
            this.y = random(this.bounds["y"].min, this.bounds["y"].max);

            // how large the orb is vs it's original radius (this will modulate over time)
            this.scale = 1;

            // what color is the orb?
            this.fill = fill;

            // the original radius of the orb, set relative to window height
            this.radius = random(window.innerHeight / 6, window.innerHeight / 3);

            // starting points in "time" for the noise/self similar random values
            this.xOff = random(0, 1000);
            this.yOff = random(0, 1000);
            // how quickly the noise/self similar random values step through time
            this.inc = 0.002;

            // PIXI.Graphics is used to draw 2d primitives (in this case a circle) to the canvas
            this.graphics = new PIXI.Graphics();
            this.graphics.alpha = 0.825;

            // 250ms after the last window resize event, recalculate orb positions.
            window.addEventListener(
                "resize",
                debounce(() => {
                    this.bounds = this.setBounds();
                }, 250)
            );
        }

        setBounds() {
            // how far from the { x, y } origin can each orb move
            const maxDist =
                window.innerWidth < 1000 ? window.innerWidth / 3 : window.innerWidth / 5;
            // the { x, y } origin for each orb (the bottom right of the screen)
            const originX = window.innerWidth / 1.25;
            const originY =
                window.innerWidth < 1000 ?
                window.innerHeight :
                window.innerHeight / 1.375;

            // allow each orb to move x distance away from it's x / y origin
            return {
                x: {
                    min: originX - maxDist,
                    max: originX + maxDist
                },
                y: {
                    min: originY - maxDist,
                    max: originY + maxDist
                }
            };
        }

        update() {
            // self similar "psuedo-random" or noise values at a given point in "time"
            const xNoise = simplex.noise2D(this.xOff, this.xOff);
            const yNoise = simplex.noise2D(this.yOff, this.yOff);
            const scaleNoise = simplex.noise2D(this.xOff, this.yOff);

            // map the xNoise/yNoise values (between -1 and 1) to a point within the orb's bounds
            this.x = map(xNoise, -1, 1, this.bounds["x"].min, this.bounds["x"].max);
            this.y = map(yNoise, -1, 1, this.bounds["y"].min, this.bounds["y"].max);
            // map scaleNoise (between -1 and 1) to a scale value somewhere between half of the orb's original size, and 100% of it's original size
            this.scale = map(scaleNoise, -1, 1, 0.5, 1);

            // step through "time"
            this.xOff += this.inc;
            this.yOff += this.inc;
        }

        render() {
            // update the PIXI.Graphics position and scale values
            this.graphics.x = this.x;
            this.graphics.y = this.y;
            this.graphics.scale.set(this.scale);

            // clear anything currently drawn to graphics
            this.graphics.clear();

            // tell graphics to fill any shapes drawn after this with the orb's fill color
            this.graphics.beginFill(this.fill);
            // draw a circle at { 0, 0 } with it's size set by this.radius
            this.graphics.drawCircle(0, 0, this.radius);
            // let graphics know we won't be filling in any more shapes
            this.graphics.endFill();
        }
    }

    // Create PixiJS app
    const app = new PIXI.Application({
        // render to <canvas class="orb-canvas"></canvas>
        view: document.querySelector(".orb-canvas"),
        // auto adjust size to fit the current window
        resizeTo: window,
        // transparent background, we will be creating a gradient background later using CSS
        transparent: true
    });

    app.stage.filters = [new KawaseBlurFilter(30, 10, true)];

    // Create colour palette
    const colorPalette = new ColorPalette();

    // Create orbs
    const orbs = [];

    for (let i = 0; i < 10; i++) {
        const orb = new Orb(colorPalette.randomColor());

        app.stage.addChild(orb.graphics);

        orbs.push(orb);
    }

    // Animate!
    if (!window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
        app.ticker.add(() => {
            orbs.forEach((orb) => {
                orb.update();
                orb.render();
            });
        });
    } else {
        orbs.forEach((orb) => {
            orb.update();
            orb.render();
        });
    }

    document.addEventListener("DOMContentLoaded", () => {
        const button = document.querySelector(".overlay__btn--colors");
        if (button) {
            button.addEventListener("click", () => {
                colorPalette.setColors();
                colorPalette.setCustomProperties();

                orbs.forEach((orb) => {
                    orb.fill = colorPalette.randomColor();
                });
            });
        }
    });

    // document
    //     .querySelector(".overlay__btn--colors")
    //     .addEventListener("click", () => {
    //         colorPalette.setColors();
    //         colorPalette.setCustomProperties();

    //         orbs.forEach((orb) => {
    //             orb.fill = colorPalette.randomColor();
    //         });
    //     });
    // Función para copiar la contraseña al portapapeles
    function copyPassword() {
        const passwordInput = document.getElementById("password");
        passwordInput.select();
        //document.querySelector('#password').select();
        document.execCommand("copy");
        alert("Contraseña copiada al portapapeles");
    }
</script>
</body>

</html>