export interface WhoisResult {
    createdDate: string;
    ageInDays: number;
    registrar: string;
}

export async function checkWhois(hostname: string): Promise<WhoisResult> {

    const api_key = process.env.WHOIS_API_KEY;
    const res = await fetch(`https://api.ip2whois.com/v2?key=${api_key}&domain=${hostname}`);

    if (!res.ok) {
        throw new Error("Request failed");
    }

    console.log(res.json);
    const data = await res.json();
    const whoisData = createResult(data);
    return whoisData; // ← JSON object
}


function createResult(whois: any): WhoisResult {
    const currentDate = new Date();
    const currentDateDaya = currentDate.getDate()

    const created = new Date(whois.create_date);
    const current = new Date();

    const diffMs = current.getTime() - created.getTime();
    const diffDays = diffMs / (1000 * 60 * 60 * 24);

    console.log(diffDays); // 3


    return {
        createdDate: whois.create_date.split('T')[0],
        ageInDays: diffDays,
        registrar: 'Unknown Registrar',
    };
}