#!/bin/sh
# mask_to_params.sh — turn HAIL_MASK path list into {"params":{...}} by querying `cli -g`
# Usage: HAIL_MASK='["isp.exposure","video0.bitrate",...]' ./mask_to_params.sh

# --- debug (stderr only) ---
echo "HAIL_PARAMS is: ${HAIL_PARAMS:-<unset>}" >&2
echo "HAIL_DATA   is: ${HAIL_DATA:-<unset>}" >&2
echo "HAIL_MASK   is: ${HAIL_MASK:-<unset>}" >&2

# --- quick out if no mask provided ---
if [ -z "${HAIL_MASK:-}" ]; then
  printf '%s\n' '{"params":{}}'
  exit 0
fi

# --- parse mask into newline-delimited paths ---
mask_to_lines() {
  if command -v jq >/dev/null 2>&1; then
    printf '%s' "$HAIL_MASK" | jq -r '.[]'
  else
    # Minimal parser for ["a.b","c.d"] → lines; expects well-formed, quoted strings.
    printf '%s' "$HAIL_MASK" \
    | sed -e 's/^[[:space:]]*\[//' -e 's/\][[:space:]]*$//' \
    | awk 'BEGIN{RS=","; ORS="\n"} {gsub(/^[[:space:]]*"|"[[:space:]]*$/,""); if(length($0)) print $0}'
  fi
}

# --- collect path<TAB>type<TAB>value lines ---
# type = raw (numbers/true/false/null) or str (string)
collect_values() {
  while IFS= read -r path; do
    [ -z "$path" ] && continue
    key=".$path"
    val="$(cli -g "$key" 2>/dev/null || true)"

    # decide JSON type
    if [ "$val" = "true" ] || [ "$val" = "false" ] || [ "$val" = "null" ]; then
      type="raw"
    elif printf '%s' "$val" | grep -Eq '^-?[0-9]+([.][0-9]+)?$'; then
      type="raw"
    else
      type="str"
    fi

    # if completely empty (no value), skip emitting this key
    [ -z "$val" ] && continue

    # emit: path \t type \t value
    printf '%s\t%s\t%s\n' "$path" "$type" "$val"
  done
}

# --- render nested JSON from sorted path/type/value lines ---
render_json() {
  # sort ensures stable nesting order
  sort | awk -F'\t' '
  BEGIN{
    # Start outer wrapper
    printf "{\"params\":"
    # Start inner object
    printf "{"
    depth=0
  }
  # escape JSON string content (basic: \ " \n \r \t)
  function jesc(s,   t){ gsub(/\\/,"\\\\",s); gsub(/\"/,"\\\"",s); gsub(/\r/,"\\r",s); gsub(/\n/,"\\n",s); gsub(/\t/,"\\t",s); return s }

  # print comma if needed at current depth
  function comma_if_needed(d){ if(done[d]) printf ","; else done[d]=1 }

  {
    split($1, seg, "."); n=length(seg)
    type=$2; val=$3

    # Find longest common prefix with current path
    lcp=0
    for(i=1;i<=depth && i<=n;i++){ if(curr[i]==seg[i]) lcp++; else break }

    # Close objects for levels deeper than lcp
    for(i=depth; i>lcp; i--){
      printf "}"
      done[i]=0
      # After closing a level, the parent may now need commas for next siblings
    }
    depth=lcp

    # Open objects for new intermediate segments up to leaf-1
    for(i=lcp+1; i<n; i++){
      comma_if_needed(depth)     # sibling comma at current depth
      printf "\"%s\":{", seg[i]
      depth++
      done[depth]=0
      curr[depth]=seg[i]
    }

    # Leaf key
    comma_if_needed(depth)
    if(type=="str"){
      printf "\"%s\":\"%s\"", seg[n], jesc(val)
    } else {
      printf "\"%s\":%s", seg[n], val
    }

    # Update current path stack
    # Note: depth equals n-1 here (number of open objects)
    # Save leaf name for future lcp calc convenience (not strictly required)
    curr[depth+1]=seg[n]
  }
  END{
    # Close any remaining open braces
    for(i=depth; i>0; i--) printf "}"
    # Close inner object and outer wrapper
    printf "}"
    printf "}\n"
  }'
}

# --- run pipeline ---
mask_to_lines | collect_values | render_json

