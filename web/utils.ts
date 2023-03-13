

export async function get(url: string) {
    try {
        let response = await fetch(url)
        return response.json()
    } catch {
        return
    }
}


export async function post(url: string, data?: any) {
    try {
        let options: RequestInit = {
            method: 'POST',
            cache: 'no-cache',
            headers: {
                'Content-Type': 'application/json',
            },
        }
        if (data) {
            options.body = JSON.stringify(data)
        }
        let response = await fetch(url, options)
        return await response.json()
    } catch {
        return
    }
}